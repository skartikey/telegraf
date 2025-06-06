//go:generate ../../../tools/readme_config_includer/generator
//go:build windows

package win_eventlog

import (
	"bufio"
	"bytes"
	_ "embed"
	"encoding/xml"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/config"
	"github.com/influxdata/telegraf/filter"
	"github.com/influxdata/telegraf/plugins/inputs"
)

//go:embed sample.conf
var sampleConfig string

var errEventTooLarge = errors.New("event too large")

type WinEventLog struct {
	Locale                 uint32          `toml:"locale"`
	EventlogName           string          `toml:"eventlog_name"`
	Query                  string          `toml:"xpath_query"`
	FromBeginning          bool            `toml:"from_beginning"`
	BatchSize              uint32          `toml:"event_batch_size"`
	ProcessUserData        bool            `toml:"process_userdata"`
	ProcessEventData       bool            `toml:"process_eventdata"`
	Separator              string          `toml:"separator"`
	OnlyFirstLineOfMessage bool            `toml:"only_first_line_of_message"`
	TimeStampFromEvent     bool            `toml:"timestamp_from_event"`
	EventTags              []string        `toml:"event_tags"`
	EventFields            []string        `toml:"event_fields"`
	ExcludeFields          []string        `toml:"exclude_fields"`
	ExcludeEmpty           []string        `toml:"exclude_empty"`
	EventSizeLimit         config.Size     `toml:"event_size_limit"`
	Log                    telegraf.Logger `toml:"-"`

	subscription     evtHandle
	subscriptionFlag evtSubscribeFlag
	bookmark         evtHandle
	tagFilter        filter.Filter
	fieldFilter      filter.Filter
	fieldEmptyFilter filter.Filter
}

func (*WinEventLog) SampleConfig() string {
	return sampleConfig
}

func (w *WinEventLog) Init() error {
	// Set defaults
	if w.BatchSize < 1 {
		w.BatchSize = 5
	}

	w.subscriptionFlag = evtSubscribeToFutureEvents
	if w.FromBeginning {
		w.subscriptionFlag = evtSubscribeStartAtOldestRecord
	}

	if w.Query == "" {
		w.Query = "*"
	}

	if w.EventSizeLimit == 0 {
		w.EventSizeLimit = config.Size(64 * 1024) // 64kb
	} else if w.EventSizeLimit > math.MaxUint32 {
		// Clip the size to not overflow
		w.EventSizeLimit = config.Size(math.MaxUint32)
	}

	bookmark, err := evtCreateBookmark(nil)
	if err != nil {
		return err
	}
	w.bookmark = bookmark

	if w.tagFilter, err = filter.Compile(w.EventTags); err != nil {
		return fmt.Errorf("creating tag filter failed: %w", err)
	}

	if w.fieldFilter, err = filter.NewIncludeExcludeFilter(w.EventFields, w.ExcludeFields); err != nil {
		return fmt.Errorf("creating field filter failed: %w", err)
	}

	if w.fieldEmptyFilter, err = filter.Compile(w.ExcludeEmpty); err != nil {
		return fmt.Errorf("creating empty fields filter failed: %w", err)
	}

	return nil
}

func (w *WinEventLog) Start(telegraf.Accumulator) error {
	subscription, err := w.evtSubscribe()
	if err != nil {
		return fmt.Errorf("subscription of Windows Event Log failed: %w", err)
	}
	w.subscription = subscription
	w.Log.Debug("Subscription handle id:", w.subscription)

	return nil
}

func (w *WinEventLog) GetState() interface{} {
	bookmarkXML, err := w.renderBookmark()
	if err != nil {
		w.Log.Errorf("State-persistence failed, cannot render bookmark: %v", err)
		return ""
	}
	return bookmarkXML
}

func (w *WinEventLog) SetState(state interface{}) error {
	bookmarkXML, ok := state.(string)
	if !ok {
		return fmt.Errorf("invalid type %T for state", state)
	}

	ptr, err := syscall.UTF16PtrFromString(bookmarkXML)
	if err != nil {
		return fmt.Errorf("conversion to pointer failed: %w", err)
	}

	bookmark, err := evtCreateBookmark(ptr)
	if err != nil {
		return fmt.Errorf("creating bookmark failed: %w", err)
	}
	w.bookmark = bookmark
	w.subscriptionFlag = evtSubscribeStartAfterBookmark

	return nil
}

func (w *WinEventLog) Gather(acc telegraf.Accumulator) error {
	for {
		events, err := w.fetchEvents(w.subscription)
		if err != nil {
			if errors.Is(err, errNoMoreItems) {
				break
			}
			w.Log.Errorf("Error getting events: %v", err)
			return err
		}

		for i := range events {
			// Prepare fields names usage counter
			fieldsUsage := make(map[string]int)

			tags := make(map[string]string)
			fields := make(map[string]interface{})
			event := events[i]
			evt := reflect.ValueOf(&event).Elem()
			timeStamp := time.Now()
			// Walk through all fields of event struct to process System tags or fields
			for i := 0; i < evt.NumField(); i++ {
				fieldName := evt.Type().Field(i).Name
				fieldType := evt.Field(i).Type().String()
				fieldValue := evt.Field(i).Interface()
				computedValues := make(map[string]interface{})
				switch fieldName {
				case "Source":
					fieldValue = event.Source.Name
					fieldType = reflect.TypeOf(fieldValue).String()
				case "Execution":
					fieldValue := event.Execution.ProcessID
					fieldType = reflect.TypeOf(fieldValue).String()
					fieldName = "ProcessID"
					// Look up Process Name from pid
					if should, _ := w.shouldProcessField("ProcessName"); should {
						processName, err := getFromSnapProcess(fieldValue)
						if err == nil {
							computedValues["ProcessName"] = processName
						}
					}
				case "TimeCreated":
					fieldValue = event.TimeCreated.SystemTime
					fieldType = reflect.TypeOf(fieldValue).String()
					if w.TimeStampFromEvent {
						timeStamp, err = time.Parse(time.RFC3339Nano, fmt.Sprintf("%v", fieldValue))
						if err != nil {
							w.Log.Warnf("Error parsing timestamp %q: %v", fieldValue, err)
						}
					}
				case "Correlation":
					if should, _ := w.shouldProcessField("ActivityID"); should {
						activityID := event.Correlation.ActivityID
						if len(activityID) > 0 {
							computedValues["ActivityID"] = activityID
						}
					}
					if should, _ := w.shouldProcessField("RelatedActivityID"); should {
						relatedActivityID := event.Correlation.RelatedActivityID
						if len(relatedActivityID) > 0 {
							computedValues["RelatedActivityID"] = relatedActivityID
						}
					}
				case "Security":
					computedValues["UserID"] = event.Security.UserID
					// Look up UserName and Domain from SID
					if should, _ := w.shouldProcessField("UserName"); should {
						sid := event.Security.UserID
						usid, err := syscall.StringToSid(sid)
						if err == nil {
							username, domain, _, err := usid.LookupAccount("")
							if err == nil {
								computedValues["UserName"] = fmt.Sprint(domain, "\\", username)
							}
						}
					}
				}
				if should, where := w.shouldProcessField(fieldName); should {
					if where == "tags" {
						strValue := fmt.Sprintf("%v", fieldValue)
						if !w.shouldExcludeEmptyField(fieldName, "string", strValue) {
							tags[fieldName] = strValue
							fieldsUsage[fieldName]++
						}
					} else if where == "fields" {
						if !w.shouldExcludeEmptyField(fieldName, fieldType, fieldValue) {
							fields[fieldName] = fieldValue
							fieldsUsage[fieldName]++
						}
					}
				}

				// Insert computed fields
				for computedKey, computedValue := range computedValues {
					if should, where := w.shouldProcessField(computedKey); should {
						if where == "tags" {
							tags[computedKey] = fmt.Sprintf("%v", computedValue)
							fieldsUsage[computedKey]++
						} else if where == "fields" {
							fields[computedKey] = computedValue
							fieldsUsage[computedKey]++
						}
					}
				}
			}

			// Unroll additional XML
			var xmlFields []eventField
			if w.ProcessUserData {
				fieldsUserData, xmlFieldsUsage := unrollXMLFields(event.UserData.InnerXML, fieldsUsage, w.Separator)
				xmlFields = append(xmlFields, fieldsUserData...)
				fieldsUsage = xmlFieldsUsage
			}
			if w.ProcessEventData {
				fieldsEventData, xmlFieldsUsage := unrollXMLFields(event.EventData.InnerXML, fieldsUsage, w.Separator)
				xmlFields = append(xmlFields, fieldsEventData...)
				fieldsUsage = xmlFieldsUsage
			}
			uniqueXMLFields := uniqueFieldNames(xmlFields, fieldsUsage, w.Separator)
			for _, xmlField := range uniqueXMLFields {
				should, where := w.shouldProcessField(xmlField.Name)
				if !should {
					continue
				}
				if where == "tags" {
					tags[xmlField.Name] = xmlField.Value
				} else {
					fields[xmlField.Name] = xmlField.Value
				}
			}

			// Pass collected metrics
			acc.AddFields("win_eventlog", fields, tags, timeStamp)
		}
	}

	return nil
}

func (w *WinEventLog) Stop() {
	//nolint:errcheck // ending the subscription, error can be ignored
	_ = evtClose(w.subscription)
}

func (w *WinEventLog) shouldProcessField(field string) (should bool, list string) {
	if w.tagFilter != nil && w.tagFilter.Match(field) {
		return true, "tags"
	}

	if w.fieldFilter.Match(field) {
		return true, "fields"
	}

	return false, "excluded"
}

func (w *WinEventLog) shouldExcludeEmptyField(field, fieldType string, fieldValue interface{}) (should bool) {
	if w.fieldEmptyFilter == nil || !w.fieldEmptyFilter.Match(field) {
		return false
	}

	switch fieldType {
	case "string":
		return len(fieldValue.(string)) < 1
	case "int":
		return fieldValue.(int) == 0
	case "uint32":
		return fieldValue.(uint32) == 0
	}

	return false
}

func (w *WinEventLog) evtSubscribe() (evtHandle, error) {
	sigEvent, err := windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(sigEvent)

	logNamePtr, err := syscall.UTF16PtrFromString(w.EventlogName)
	if err != nil {
		return 0, err
	}

	xqueryPtr, err := syscall.UTF16PtrFromString(w.Query)
	if err != nil {
		return 0, err
	}

	var bookmark evtHandle
	if w.subscriptionFlag == evtSubscribeStartAfterBookmark {
		bookmark = w.bookmark
	}
	subsHandle, err := evtSubscribe(0, uintptr(sigEvent), logNamePtr, xqueryPtr, bookmark, 0, 0, w.subscriptionFlag)
	if err != nil {
		return 0, err
	}

	return subsHandle, nil
}

func (w *WinEventLog) fetchEventHandles(subsHandle evtHandle) ([]evtHandle, error) {
	var evtReturned uint32

	eventHandles := make([]evtHandle, w.BatchSize)
	if err := evtNext(subsHandle, w.BatchSize, &eventHandles[0], 0, 0, &evtReturned); err != nil {
		if errors.Is(err, errInvalidOperation) && evtReturned == 0 {
			return nil, errNoMoreItems
		}
		return nil, err
	}

	return eventHandles[:evtReturned], nil
}

func (w *WinEventLog) fetchEvents(subsHandle evtHandle) ([]event, error) {
	var events []event

	eventHandles, err := w.fetchEventHandles(subsHandle)
	if err != nil {
		return nil, err
	}

	var evterr error
	for _, eventHandle := range eventHandles {
		if eventHandle == 0 {
			continue
		}
		if event, err := w.renderEvent(eventHandle); err != nil {
			w.Log.Errorf("Rendering event failed: %v", err)
		} else {
			events = append(events, event)
		}

		if err := evtUpdateBookmark(w.bookmark, eventHandle); err != nil {
			w.Log.Errorf("Updateing bookmark failed: %v", err)
			if evterr == nil {
				evterr = err
			}
		}

		if err := evtClose(eventHandle); err != nil {
			w.Log.Errorf("Closing event failed: %v", err)
			if evterr == nil {
				evterr = err
			}
		}
	}
	return events, evterr
}

func (w *WinEventLog) renderBookmark() (string, error) {
	// Determine the buffer size required
	var used uint32
	err := evtRender(w.bookmark, evtRenderBookmark, 0, nil, &used)
	if err != nil && !errors.Is(err, errInsufficientBuffer) {
		return "", err
	}

	// Actually retrieve the data
	buf := make([]byte, used)
	if err := evtRender(w.bookmark, evtRenderBookmark, uint32(len(buf)), &buf[0], &used); err != nil {
		return "", err
	}

	// Decocde the charset
	decoded, err := decodeUTF16(buf[:used])
	if err != nil {
		return "", err
	}
	// Strip the trailing null character if any
	if decoded[len(decoded)-1] == 0 {
		decoded = decoded[:len(decoded)-1]
	}

	return string(decoded), err
}

func (w *WinEventLog) renderEvent(eventHandle evtHandle) (event, error) {
	// Determine the size of the buffer and grow the buffer if necessary
	var used uint32
	err := evtRender(eventHandle, evtRenderEventXML, 0, nil, &used)
	if err != nil && !errors.Is(err, errInsufficientBuffer) {
		return event{}, err
	}

	// If the event size exceeds the limit exit early as truncating the event
	// data would destroy the XML structure.
	if used > uint32(w.EventSizeLimit) {
		return event{}, errEventTooLarge
	}

	// Actually retrieve the event
	buf := make([]byte, used)
	if err := evtRender(eventHandle, evtRenderEventXML, uint32(len(buf)), &buf[0], &used); err != nil {
		return event{}, err
	}

	// Decode the charset
	eventXML, err := decodeUTF16(buf[:used])
	if err != nil {
		return event{}, err
	}

	// Unmarshal the event XML. For forwarded events, this can fail but we can
	// return the event without most text values, that way we will not lose
	// information.
	var evt event
	if err := xml.Unmarshal(eventXML, &evt); err != nil {
		//nolint:nilerr // This can happen when processing Forwarded Events
		return evt, nil
	}

	// Do resolve local messages the usual way, while using built-in information for events forwarded by WEC.
	// This is a safety measure as the underlying Windows-internal EvtFormatMessage might segfault in cases
	// where the publisher (i.e. the remote machine which forwarded the event) is unavailable e.g. due to
	// a reboot. See https://github.com/influxdata/telegraf/issues/12328 for the full story.
	if evt.RenderingInfo == nil {
		return w.renderLocalMessage(evt, eventHandle)
	}

	// We got 'RenderInfo' elements, so try to apply them in the following function
	return w.renderRemoteMessage(evt)
}

func (w *WinEventLog) renderLocalMessage(event event, eventHandle evtHandle) (event, error) {
	publisherHandle, err := openPublisherMetadata(0, event.Source.Name, w.Locale)
	if err != nil {
		return event, nil
	}
	defer evtClose(publisherHandle) //nolint:errcheck // Ignore error returned during Close

	// Populating text values
	keywords, err := formatEventString(evtFormatMessageKeyword, eventHandle, publisherHandle)
	if err == nil {
		event.Keywords = keywords
	}
	message, err := formatEventString(evtFormatMessageEvent, eventHandle, publisherHandle)
	if err == nil {
		if w.OnlyFirstLineOfMessage {
			scanner := bufio.NewScanner(strings.NewReader(message))
			scanner.Scan()
			message = scanner.Text()
		}
		event.Message = message
	}
	level, err := formatEventString(evtFormatMessageLevel, eventHandle, publisherHandle)
	if err == nil {
		event.LevelText = level
	}
	task, err := formatEventString(evtFormatMessageTask, eventHandle, publisherHandle)
	if err == nil {
		event.TaskText = task
	}
	opcode, err := formatEventString(evtFormatMessageOpcode, eventHandle, publisherHandle)
	if err == nil {
		event.OpcodeText = opcode
	}
	return event, nil
}

func (w *WinEventLog) renderRemoteMessage(event event) (event, error) {
	// Populating text values from RenderingInfo part of the XML
	if len(event.RenderingInfo.Keywords) > 0 {
		event.Keywords = strings.Join(event.RenderingInfo.Keywords, ",")
	}
	if event.RenderingInfo.Message != "" {
		message := event.RenderingInfo.Message
		if w.OnlyFirstLineOfMessage {
			scanner := bufio.NewScanner(strings.NewReader(message))
			scanner.Scan()
			message = scanner.Text()
		}
		event.Message = message
	}
	if event.RenderingInfo.Level != "" {
		event.LevelText = event.RenderingInfo.Level
	}
	if event.RenderingInfo.Task != "" {
		event.TaskText = event.RenderingInfo.Task
	}
	if event.RenderingInfo.Opcode != "" {
		event.OpcodeText = event.RenderingInfo.Opcode
	}
	return event, nil
}

func formatEventString(messageFlag evtFormatMessageFlag, eventHandle, publisherHandle evtHandle) (string, error) {
	var bufferUsed uint32
	err := evtFormatMessage(publisherHandle, eventHandle, 0, 0, 0, messageFlag, 0, nil, &bufferUsed)
	if err != nil && !errors.Is(err, errInsufficientBuffer) {
		return "", err
	}

	// Handle empty elements
	if bufferUsed < 1 {
		return "", nil
	}

	bufferUsed *= 2
	buffer := make([]byte, bufferUsed)
	bufferUsed = 0

	err = evtFormatMessage(publisherHandle, eventHandle, 0, 0, 0, messageFlag,
		uint32(len(buffer)/2), &buffer[0], &bufferUsed)
	if err != nil {
		return "", err
	}
	bufferUsed *= 2

	result, err := decodeUTF16(buffer[:bufferUsed])
	if err != nil {
		return "", err
	}

	var out string
	if messageFlag == evtFormatMessageKeyword {
		// Keywords are returned as array of a zero-terminated strings
		splitZero := func(c rune) bool { return c == '\x00' }
		eventKeywords := strings.FieldsFunc(string(result), splitZero)
		// So convert them to comma-separated string
		out = strings.Join(eventKeywords, ",")
	} else {
		result := bytes.Trim(result, "\x00")
		out = string(result)
	}
	return out, nil
}

// openPublisherMetadata opens a handle to the publisher's metadata. Close must
// be called on returned evtHandle when finished with the handle.
func openPublisherMetadata(session evtHandle, publisherName string, lang uint32) (evtHandle, error) {
	p, err := syscall.UTF16PtrFromString(publisherName)
	if err != nil {
		return 0, err
	}

	h, err := evtOpenPublisherMetadata(session, p, nil, lang, 0)
	if err != nil {
		return 0, err
	}

	return h, nil
}

func init() {
	inputs.Add("win_eventlog", func() telegraf.Input {
		return &WinEventLog{
			ProcessUserData:        true,
			ProcessEventData:       true,
			Separator:              "_",
			OnlyFirstLineOfMessage: true,
			TimeStampFromEvent:     true,
			EventTags:              []string{"Source", "EventID", "Level", "LevelText", "Keywords", "Channel", "Computer"},
			ExcludeEmpty:           []string{"Task", "Opcode", "*ActivityID", "UserID"},
		}
	})
}
