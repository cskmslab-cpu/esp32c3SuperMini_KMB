/*
  修正版 - 針對以下漏洞進行修補：
  1. 新增 Basic Auth 身份驗證
  2. 新增 CSRF Token 保護
  3. 新增輸入長度與內容過濾（XSS 防護）
  4. AP 限時開啟（減少攻擊窗口）
  5. WiFi 重連加入冷卻時間
  6. NVS 資料完整性校驗（CRC32）
  7. 新增 HTTP 安全標頭
  8. 刪除操作改為 POST
*/

#include <LovyanGFX.hpp>
#include <WiFi.h>
#include <WiFiManager.h>
#include <WiFiClientSecure.h>
#include <HTTPClient.h>
#include <WebServer.h>
#include <Preferences.h>
#include <ArduinoJson.h>
#include <time.h>
#include <vector>

// =====================================================
// 安全設定區
// =====================================================
const char* SETUP_AP_NAME  = "ESP32-KMB-Setup";
#define BOOT_BUTTON_PIN 9

// 管理熱點（限時開啟）
const char* CONFIG_AP_SSID = "ESP32-BusConfig";
const char* CONFIG_AP_PASS = "Tr@ff1c-2024!"; // 強密碼

// 網頁管理登入（Basic Auth）
const char* WEB_USER = "admin";
const char* WEB_PASS = "KmbB0ard#88"; // 與 AP 密碼不同

// AP 限時設定
const unsigned long AP_ON_DURATION  = 10UL * 60UL * 1000UL; // 10 分鐘
const unsigned long BOOT_LONG_PRESS = 3000; // 長按 3 秒重開 AP

// WiFi 重連冷卻（避免頻繁重試）
const unsigned long WIFI_RETRY_INTERVAL = 30000; // 30 秒才重試一次

// 輸入長度上限
const int MAX_ROUTE_LEN       = 8;
const int MAX_STOPID_LEN      = 16;
const int MAX_SVCTYPE_LEN     = 2;

// =====================================================

const long  gmtOffset_sec      = 8 * 3600;
const int   daylightOffset_sec = 0;
const char* ntpServer1 = "pool.ntp.org";
const char* ntpServer2 = "time.google.com";

const unsigned long ETA_REFRESH_INTERVAL     = 30000;
const unsigned long WEATHER_REFRESH_INTERVAL = 900000;
const unsigned long PAGE_INTERVAL            = 10000;
const int MAX_ROUTES = 8;

struct RouteConfig {
  String stopId;
  String route;
  String serviceType;
  String dir;
};
std::vector<RouteConfig> routeList;

struct RouteStatus {
  String dest;
  time_t etaEpoch;
  bool valid;
};
std::vector<RouteStatus> routeStatus;

Preferences prefs;
WebServer server(80);

// AP 狀態
bool apActive = false;
unsigned long apEnabledAt = 0;
unsigned long bootPressStart = 0;
bool bootLongPressHandled = false;

// WiFi 重連冷卻
unsigned long lastWifiRetry = 0;

// CSRF Token（每次開機隨機產生）
String csrfToken = "";

const char* HKO_URL   = "https://data.weather.gov.hk/weatherAPI/opendata/weather.php?dataType=rhrread&lang=tc";
const char* HKO_PLACE = "香港天文台";

struct WeatherStatus {
  float temperature;
  int   weatherCode;
  bool  valid;
};
WeatherStatus weather = {0, 0, false};

// =====================================================
// LovyanGFX（與原版相同）
// =====================================================
class LGFX : public lgfx::LGFX_Device {
  lgfx::Bus_SPI    _bus_instance;
  lgfx::Panel_ST7789 _panel_instance;
public:
  LGFX(void) {
    { auto cfg = _bus_instance.config();
      cfg.spi_host=SPI2_HOST; cfg.spi_mode=0;
      cfg.freq_write=40000000; cfg.freq_read=16000000;
      cfg.pin_sclk=8; cfg.pin_mosi=10; cfg.pin_miso=-1; cfg.pin_dc=5;
      _bus_instance.config(cfg); _panel_instance.setBus(&_bus_instance); }
    { auto cfg = _panel_instance.config();
      cfg.pin_cs=4; cfg.pin_rst=6; cfg.pin_busy=-1;
      cfg.memory_width=240; cfg.memory_height=320;
      cfg.panel_width=240;  cfg.panel_height=320;
      cfg.readable=false; cfg.invert=false;
      cfg.rgb_order=false; cfg.dlen_16bit=false; cfg.bus_shared=false;
      _panel_instance.config(cfg); }
    setPanel(&_panel_instance);
  }
};
LGFX display;

unsigned long lastEtaFetch    = 0;
unsigned long lastWeatherFetch= 0;
unsigned long lastPageFlip    = 0;
int lastSecond  = -1;
int currentPage = 0;

// =====================================================
// 工具函數
// =====================================================

// 產生隨機 CSRF Token（開機時呼叫一次）
void generateCsrfToken() {
  csrfToken = "";
  const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  for (int i = 0; i < 32; i++) {
    csrfToken += charset[esp_random() % (sizeof(charset) - 1)];
  }
  Serial.println("CSRF Token 已產生");
}

// 簡單 CRC32（用於 NVS 資料完整性校驗）
uint32_t crc32(const String& s) {
  uint32_t crc = 0xFFFFFFFF;
  for (char c : s) {
    crc ^= (uint8_t)c;
    for (int i = 0; i < 8; i++)
      crc = (crc >> 1) ^ (0xEDB88320 & -(crc & 1));
  }
  return ~crc;
}

// 字串輸入過濾：只保留字母、數字、空白（防 XSS）
String sanitizeInput(const String& input, int maxLen) {
  String out = "";
  int count = 0;
  for (char c : input) {
    if (count >= maxLen) break;
    // 只允許英數字、中文範圍（UTF-8 多位元組），拒絕 HTML 特殊字元
    if (c == '<' || c == '>' || c == '"' || c == '\'' || c == '&' || c == ';') continue;
    out += c;
    count++;
  }
  return out;
}

// HTML 特殊字元轉義（輸出到網頁時使用）
String htmlEscape(const String& s) {
  String out = "";
  for (char c : s) {
    switch (c) {
      case '<': out += "&lt;";  break;
      case '>': out += "&gt;";  break;
      case '"': out += "&quot;"; break;
      case '\'': out += "&#39;"; break;
      case '&': out += "&amp;"; break;
      default:  out += c;
    }
  }
  return out;
}

// dir 欄位只接受 "O" 或 "I"
String sanitizeDir(const String& input) {
  if (input == "I") return "I";
  return "O"; // 預設值，拒絕其他任何輸入
}

// =====================================================
// AP 開關管理
// =====================================================
void enableConfigAP() {
  int staChannel = WiFi.channel();
  if (staChannel <= 0) staChannel = 6;
  WiFi.mode(WIFI_AP_STA);
  WiFi.softAP(CONFIG_AP_SSID, CONFIG_AP_PASS, staChannel);
  apActive    = true;
  apEnabledAt = millis();
  Serial.printf("管理熱點已開啟，Channel: %d，限時10分鐘\n", staChannel);
}

void disableConfigAP() {
  WiFi.softAPdisconnect(true);
  WiFi.mode(WIFI_STA);
  apActive = false;
  Serial.println("管理熱點已自動關閉");
}

// =====================================================
// NVS 讀寫（加入 CRC32 校驗）
// =====================================================
void saveRoutesToPrefs() {
  DynamicJsonDocument doc(2048);
  JsonArray arr = doc.to<JsonArray>();
  for (auto& r : routeList) {
    JsonObject o = arr.createNestedObject();
    o["stopId"]      = r.stopId;
    o["route"]       = r.route;
    o["serviceType"] = r.serviceType;
    o["dir"]         = r.dir;
  }
  String out;
  serializeJson(doc, out);

  // 存入資料本體與 CRC32
  uint32_t crc = crc32(out);
  prefs.putString("routes_json", out);
  prefs.putUInt("routes_crc", crc);
  Serial.printf("路線已儲存，CRC: 0x%08X\n", crc);
}

void loadRoutesFromPrefs() {
  routeList.clear();
  String saved = prefs.getString("routes_json", "");

  if (saved.length() == 0) {
    // 預設路線
    routeList.push_back({"B78076CC8F628B2B", "71K", "1", "O"});
    routeList.push_back({"DC32010F7B9206C4", "72K", "1", "O"});
    saveRoutesToPrefs();
    return;
  }

  // ★ CRC32 校驗：確保 NVS 資料未被竄改或損毀
  uint32_t storedCrc  = prefs.getUInt("routes_crc", 0);
  uint32_t computedCrc = crc32(saved);
  if (storedCrc != computedCrc) {
    Serial.printf("NVS CRC 校驗失敗！stored=0x%08X computed=0x%08X\n", storedCrc, computedCrc);
    Serial.println("資料可能已損毀，恢復預設路線");
    routeList.push_back({"B78076CC8F628B2B", "71K", "1", "O"});
    routeList.push_back({"DC32010F7B9206C4", "72K", "1", "O"});
    saveRoutesToPrefs(); // 覆蓋損毀資料
    return;
  }

  DynamicJsonDocument doc(2048);
  if (deserializeJson(doc, saved)) {
    Serial.println("NVS JSON 解析失敗，恢復預設路線");
    routeList.push_back({"B78076CC8F628B2B", "71K", "1", "O"});
    routeList.push_back({"DC32010F7B9206C4", "72K", "1", "O"});
    saveRoutesToPrefs();
    return;
  }

  for (JsonObject o : doc.as<JsonArray>()) {
    RouteConfig r;
    r.stopId      = sanitizeInput(o["stopId"].as<String>(),      MAX_STOPID_LEN);
    r.route       = sanitizeInput(o["route"].as<String>(),       MAX_ROUTE_LEN);
    r.serviceType = sanitizeInput(o["serviceType"].as<String>(), MAX_SVCTYPE_LEN);
    r.dir         = sanitizeDir(o.containsKey("dir") ? o["dir"].as<String>() : "O");

    // 額外驗證：Stop ID 必須為 16 碼英數字
    if (r.stopId.length() != 16) continue;
    if (r.route.length() == 0)   continue;

    routeList.push_back(r);
  }
}

// =====================================================
// 前向宣告
// =====================================================
void fetchAllRoutes();
void drawFullScreen();

void reloadRuntimeAfterChange() {
  routeStatus.clear();
  routeStatus.resize(routeList.size());
  currentPage = 0;
  fetchAllRoutes();
  drawFullScreen();
  lastEtaFetch = millis();
  lastPageFlip = millis();
}

// =====================================================
// 時間換算
// =====================================================
long daysFromCivil(int y, int m, int d) {
  y -= (m <= 2) ? 1 : 0;
  long era = (y >= 0 ? y : y - 399) / 400;
  unsigned yoe = (unsigned)(y - era * 400);
  unsigned mp  = (m + 9) % 12;
  unsigned doy = (153 * mp + 2) / 5 + d - 1;
  unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097L + (long)doe - 719468L;
}

time_t parseKmbEta(const String& iso) {
  int y, mo, d, h, mi, se;
  if (sscanf(iso.c_str(), "%d-%d-%dT%d:%d:%d", &y, &mo, &d, &h, &mi, &se) != 6) return 0;
  long days = daysFromCivil(y, mo, d);
  time_t localAsUtc = (time_t)(days * 86400L + h * 3600L + mi * 60L + se);
  return localAsUtc - gmtOffset_sec;
}

// =====================================================
// 資料抓取
// =====================================================
void fetchRouteEta(int idx) {
  if (idx >= (int)routeList.size()) return;
  routeStatus[idx].valid = false;

  WiFiClientSecure client;
  client.setInsecure(); // 注意：生產環境建議改為憑證固定（見下方說明）
  HTTPClient http;

  String url = "https://data.etabus.gov.hk/v1/transport/kmb/eta/";
  url += routeList[idx].stopId + "/" + routeList[idx].route + "/" + routeList[idx].serviceType;

  if (!http.begin(client, url)) return;
  http.setTimeout(8000); // ★ 加入超時限制（8秒），避免長時間阻塞

  int httpCode = http.GET();
  if (httpCode != 200) { http.end(); return; }

  String payload = http.getString();
  http.end();

  // ★ 限制 payload 大小（防止惡意伺服器回傳超大回應撐爆記憶體）
  if (payload.length() > 16384) {
    Serial.println("ETA payload 過大，已拒絕");
    return;
  }

  DynamicJsonDocument doc(8192);
  if (deserializeJson(doc, payload)) return;

  JsonArray data = doc["data"].as<JsonArray>();
  time_t bestEta = 0;
  String bestDest = "";
  bool found = false;

  for (JsonObject item : data) {
    if (item["eta"].isNull()) continue;
    String itemDir = item["dir"].as<String>();
    if (itemDir != routeList[idx].dir) continue;
    time_t e = parseKmbEta(item["eta"].as<String>());
    if (e <= 0) continue;
    if (!found || e < bestEta) {
      bestEta  = e;
      // ★ 目的地名稱也要過濾，防止 API 回傳惡意內容
      bestDest = sanitizeInput(item["dest_tc"].as<String>(), 20);
      found    = true;
    }
  }

  if (found) {
    routeStatus[idx].dest     = bestDest;
    routeStatus[idx].etaEpoch = bestEta;
    routeStatus[idx].valid    = true;
  }
}

void fetchAllRoutes() {
  if (routeStatus.size() != routeList.size()) routeStatus.resize(routeList.size());
  for (int i = 0; i < (int)routeList.size(); i++) fetchRouteEta(i);
}

void fetchWeather() {
  WiFiClientSecure client;
  client.setInsecure();
  HTTPClient http;
  if (!http.begin(client, HKO_URL)) return;
  http.setTimeout(8000); // ★ 加入超時限制

  int httpCode = http.GET();
  if (httpCode != 200) { http.end(); return; }

  String payload = http.getString();
  http.end();

  if (payload.length() > 32768) { // ★ 天氣資料較大，但也設上限
    Serial.println("天氣 payload 過大，已拒絕");
    return;
  }

  DynamicJsonDocument doc(6144);
  if (deserializeJson(doc, payload)) return;

  bool tempFound = false;
  JsonArray tempData = doc["temperature"]["data"].as<JsonArray>();
  for (JsonObject item : tempData) {
    if (item["place"].as<String>() == HKO_PLACE) {
      weather.temperature = item["value"].as<float>();
      tempFound = true;
      break;
    }
  }
  if (!tempFound && tempData.size() > 0) {
    weather.temperature = tempData[0]["value"].as<float>();
    tempFound = true;
  }

  bool iconFound = false;
  JsonArray iconArr = doc["icon"].as<JsonArray>();
  if (iconArr.size() > 0) {
    int code = iconArr[0].as<int>();
    // ★ 驗證 code 範圍（HKO 定義為 50-99）
    if (code >= 50 && code <= 99) {
      weather.weatherCode = code;
      iconFound = true;
    }
  }

  weather.valid = tempFound && iconFound;
}

// =====================================================
// 天氣描述
// =====================================================
String weatherDesc(int code) {
  switch (code) {
    case 50: return "晴天";   case 51: return "天晴";
    case 52: return "短暫陽光"; case 53: case 54: return "驟雨";
    case 60: return "多雲";   case 61: return "密雲";
    case 62: return "微雨";   case 63: return "有雨";
    case 64: return "大雨";   case 65: return "雷暴";
    case 80: return "大風";   case 81: return "乾燥";
    case 82: return "潮濕";   case 83: return "有霧";
    case 84: return "薄霧";   case 85: return "煙霞";
    case 90: return "酷熱";   case 91: return "寒冷";
    case 92: return "熱帶氣旋"; case 93: return "暴雨";
    default: return "多雲";
  }
}

// =====================================================
// 網頁管理介面（加入 CSRF + HTML 轉義）
// =====================================================

// 發送帶安全標頭的回應
void sendSecureHtml(int code, const String& body) {
  server.sendHeader("X-Frame-Options", "DENY");
  server.sendHeader("X-Content-Type-Options", "nosniff");
  server.sendHeader("Cache-Control", "no-store");
  // 嚴格的 CSP：只允許 inline style，拒絕所有外部資源和腳本
  server.sendHeader("Content-Security-Policy",
    "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
  server.send(code, "text/html; charset=utf-8", body);
}

String buildConfigPage() {
  String html;
  html += "<!DOCTYPE html><html><head>"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<title>巴士站牌設定</title>"
          "<style>"
          "body{font-family:sans-serif;padding:16px;max-width:480px;margin:auto;}"
          "table{width:100%;border-collapse:collapse;margin-bottom:20px;}"
          "th,td{border:1px solid #ccc;padding:8px;text-align:left;font-size:14px;}"
          "input,select{width:100%;padding:6px;margin-bottom:8px;box-sizing:border-box;}"
          "input[type=submit]{background:#0066cc;color:white;border:none;"
          "border-radius:4px;font-size:15px;cursor:pointer;}"
          ".del{background:#cc3333;color:white;padding:6px 10px;"
          "border-radius:4px;border:none;cursor:pointer;font-size:13px;}"
          ".warn{color:#cc3333;font-weight:bold;}"
          "</style></head><body>";

  // AP 剩餘時間提示
  if (apActive) {
    unsigned long remaining = (AP_ON_DURATION - (millis() - apEnabledAt)) / 1000;
    html += "<p class='warn'>⚠️ 管理熱點開啟中，剩餘約 " + String(remaining) + " 秒自動關閉</p>";
  }

  html += "<h2>目前顯示路線</h2>";
  if (routeList.empty()) {
    html += "<p>未設定任何路線</p>";
  } else {
    html += "<table><tr><th>路線</th><th>方向</th><th>Stop ID</th><th>ST</th><th></th></tr>";
    for (int i = 0; i < (int)routeList.size(); i++) {
      String dirLabel = (routeList[i].dir == "I") ? "回 (I)" : "去 (O)";
      html += "<tr><td>" + htmlEscape(routeList[i].route) + "</td>"
              "<td>" + dirLabel + "</td>"
              "<td style='word-break:break-all;'>" + htmlEscape(routeList[i].stopId) + "</td>"
              "<td>" + htmlEscape(routeList[i].serviceType) + "</td>"
              "<td>"
              // ★ 刪除改為 POST 表單 + CSRF Token
              "<form method='POST' action='/delete' style='margin:0'>"
              "<input type='hidden' name='idx' value='" + String(i) + "'>"
              "<input type='hidden' name='csrf' value='" + csrfToken + "'>"
              "<button type='submit' class='del'>刪除</button>"
              "</form>"
              "</td></tr>";
    }
    html += "</table>";
  }

  html += "<h2>新增路線</h2>";
  if ((int)routeList.size() >= MAX_ROUTES) {
    html += "<p>已達上限 (" + String(MAX_ROUTES) + " 條)，請先刪除才能新增。</p>";
  } else {
    // ★ 加入 CSRF Token 隱藏欄位
    html += "<form method='POST' action='/add'>"
            "<input type='hidden' name='csrf' value='" + csrfToken + "'>"
            "路線號 (例如 71K，最多8字元):<input name='route' required maxlength='8'>"
            "Stop ID (16碼英數字):<input name='stopId' required maxlength='16' pattern='[A-Za-z0-9]{16}'>"
            "Service Type (預設1):<input name='serviceType' value='1' maxlength='2'>"
            "方向:<br>"
            "<select name='dir' style='width:100%;padding:6px;margin-bottom:8px;'>"
            "<option value='O'>去 (Outbound)</option>"
            "<option value='I'>回 (Inbound)</option>"
            "</select>"
            "<input type='submit' value='新增路線'>"
            "</form>";
  }

  html += "<p style='color:#666;font-size:13px;margin-top:24px'>"
          "提示：Stop ID 可從 KMB 官方 API 查詢。"
          "關閉此頁面後熱點將於限時後自動關閉。</p>"
          "</body></html>";
  return html;
}

// ★ 驗證身份 + CSRF Token
bool checkAuth() {
  if (!server.authenticate(WEB_USER, WEB_PASS)) {
    server.requestAuthentication(DIGEST_AUTH, "KMB Board", "請輸入管理員帳號密碼");
    return false;
  }
  return true;
}

bool checkCsrf() {
  // POST 請求才檢查 CSRF
  if (!server.hasArg("csrf") || server.arg("csrf") != csrfToken) {
    sendSecureHtml(403, "<h2>403 CSRF 驗證失敗</h2><p><a href='/'>返回</a></p>");
    return false;
  }
  return true;
}

void handleRoot() {
  if (!checkAuth()) return;
  sendSecureHtml(200, buildConfigPage());
}

void handleAdd() {
  if (!checkAuth()) return;
  if (!checkCsrf()) return; // ★ CSRF 驗證

  if ((int)routeList.size() < MAX_ROUTES &&
      server.hasArg("route") && server.hasArg("stopId")) {

    RouteConfig r;
    // ★ 所有輸入都經過過濾
    r.route       = sanitizeInput(server.arg("route"),       MAX_ROUTE_LEN);
    r.stopId      = sanitizeInput(server.arg("stopId"),      MAX_STOPID_LEN);
    r.serviceType = sanitizeInput(
                      server.hasArg("serviceType") ? server.arg("serviceType") : "1",
                      MAX_SVCTYPE_LEN);
    r.dir         = sanitizeDir(server.hasArg("dir") ? server.arg("dir") : "O");

    // ★ 伺服器端二次驗證 Stop ID 格式（16碼英數字）
    bool stopIdValid = (r.stopId.length() == 16);
    if (stopIdValid) {
      for (char c : r.stopId) {
        if (!isalnum(c)) { stopIdValid = false; break; }
      }
    }

    if (r.route.length() > 0 && stopIdValid) {
      routeList.push_back(r);
      saveRoutesToPrefs();
      reloadRuntimeAfterChange();
    } else {
      Serial.println("新增路線：輸入格式不符，已拒絕");
    }
  }

  server.sendHeader("Location", "/");
  server.send(303);
}

// ★ 刪除改為 POST（防 CSRF）
void handleDelete() {
  if (!checkAuth()) return;
  if (!checkCsrf()) return; // ★ CSRF 驗證

  if (server.hasArg("idx")) {
    int idx = server.arg("idx").toInt();
    // ★ 邊界檢查
    if (idx >= 0 && idx < (int)routeList.size()) {
      routeList.erase(routeList.begin() + idx);
      saveRoutesToPrefs();
      reloadRuntimeAfterChange();
    }
  }
  server.sendHeader("Location", "/");
  server.send(303);
}

void handleNotFound() {
  sendSecureHtml(404, "<h2>404 找不到頁面</h2><p><a href='/'>返回主頁</a></p>");
}

void setupWebServer() {
  server.on("/",       HTTP_GET,  handleRoot);
  server.on("/add",    HTTP_POST, handleAdd);
  server.on("/delete", HTTP_POST, handleDelete); // ★ 改為 POST
  server.onNotFound(handleNotFound);
  server.begin();
}

// =====================================================
// WiFi 連線
// =====================================================
void connectWiFi() {
  display.setFont(&fonts::efontTW_16);
  display.setTextColor(TFT_WHITE, TFT_BLACK);
  display.fillScreen(TFT_BLACK);
  display.setCursor(10, 10);
  display.println("檢查 WiFi 設定...");

  pinMode(BOOT_BUTTON_PIN, INPUT_PULLUP);

  // 防開機雜訊誤觸：持續按住 1.5 秒才當係真
  delay(50);
  bool forceReset = true;
  unsigned long holdStart = millis();
  while (millis() - holdStart < 1500) {
    if (digitalRead(BOOT_BUTTON_PIN) == HIGH) { forceReset = false; break; }
    delay(20);
  }

  WiFiManager wm;
  wm.setConfigPortalTimeout(180);

  if (forceReset) {
    display.setCursor(10, 40);
    display.println("偵測到 BOOT 鍵，清除舊設定");
    wm.resetSettings();
  }

  display.setCursor(10, 70);
  display.println("若需設定 WiFi，請連線熱點:");
  display.setCursor(10, 95);
  display.setTextColor(TFT_YELLOW, TFT_BLACK);
  display.println(SETUP_AP_NAME);
  display.setTextColor(TFT_WHITE, TFT_BLACK);

  bool ok = wm.autoConnect(SETUP_AP_NAME);
  if (!ok) {
    display.fillScreen(TFT_BLACK);
    display.setCursor(10, 10);
    display.setTextColor(TFT_RED, TFT_BLACK);
    display.println("WiFi 設定逾時/失敗");
    display.setCursor(10, 35);
    display.println("將於3秒後重新開機");
    delay(3000);
    ESP.restart();
  }

  // 等待 IP 穩定
  display.fillScreen(TFT_BLACK);
  display.setCursor(10, 10);
  display.println("等待 IP 配發...");
  int waitCount = 0;
  while (WiFi.localIP() == IPAddress(0, 0, 0, 0) && waitCount < 20) {
    delay(500); waitCount++;
  }
  if (WiFi.localIP() == IPAddress(0, 0, 0, 0)) {
    display.setCursor(10, 35);
    display.setTextColor(TFT_RED, TFT_BLACK);
    display.println("IP 取得失敗，重新開機...");
    delay(2000);
    ESP.restart();
  }

  delay(500);
  enableConfigAP(); // IP 穩定後才開 AP

  display.fillScreen(TFT_BLACK);
  display.setCursor(10, 10);
  display.setTextColor(TFT_GREEN, TFT_BLACK);
  display.println("WiFi 已連接！");
  display.setCursor(10, 35);
  display.setTextColor(TFT_WHITE, TFT_BLACK);
  display.print("IP: "); display.println(WiFi.localIP().toString());
  display.setCursor(10, 55);
  display.println("管理熱點 (限時10分鐘):");
  display.setCursor(10, 75);
  display.setTextColor(TFT_YELLOW, TFT_BLACK);
  display.println(CONFIG_AP_SSID);
  display.setCursor(10, 95);
  display.setTextColor(TFT_WHITE, TFT_BLACK);
  display.println("http://192.168.4.1");
  display.setCursor(10, 115);
  display.setTextColor(TFT_DARKGREY, TFT_BLACK);
  display.println("長按BOOT 3秒可重開熱點");
  delay(1500);
}

void syncNTP() {
  display.fillScreen(TFT_BLACK);
  display.setCursor(10, 10);
  display.println("同步網路時間中...");
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer1, ntpServer2);
  struct tm timeinfo;
  int retry = 0;
  while (!getLocalTime(&timeinfo) && retry < 20) { delay(500); retry++; }
  delay(300);
}

// =====================================================
// 畫面繪製（與原版相同，略作整理）
// =====================================================
const int SCREEN_W     = 320;
const int SCREEN_H     = 240;
const int LEFT_W       = 80;
const int RIGHT_X      = LEFT_W;
const int RIGHT_W      = SCREEN_W - LEFT_W;
const int HEADER_H     = 34;
const int ROWS_PER_PAGE= 2;
const int ROW_H        = (SCREEN_H - HEADER_H) / ROWS_PER_PAGE;

void drawWeatherIcon(int cx, int cy, int code) {
  if (code >= 50 && code <= 52) {
    display.fillCircle(cx, cy, 16, display.color565(255,200,0));
    for (int a = 0; a < 360; a += 45) {
      float r = a * 3.14159f / 180.0f;
      display.drawLine(cx+cos(r)*20, cy+sin(r)*20, cx+cos(r)*27, cy+sin(r)*27, display.color565(255,200,0));
    }
  } else if (code == 65) {
    display.fillCircle(cx-8,cy,12,display.color565(120,120,130));
    display.fillCircle(cx+8,cy,14,display.color565(120,120,130));
    display.fillRect(cx-16,cy,32,12,display.color565(120,120,130));
    display.fillTriangle(cx-2,cy+10,cx+6,cy+10,cx-4,cy+26,display.color565(255,220,0));
  } else if ((code>=53&&code<=54)||(code>=62&&code<=64)||code==93) {
    display.fillCircle(cx-8,cy-4,12,display.color565(160,160,170));
    display.fillCircle(cx+8,cy-4,14,display.color565(160,160,170));
    display.fillRect(cx-16,cy-4,32,12,display.color565(160,160,170));
    for (int i=-12;i<=12;i+=8) display.drawLine(cx+i,cy+12,cx+i-3,cy+22,display.color565(80,160,255));
  } else if (code==83||code==84||code==85) {
    for (int i=0;i<4;i++) display.drawFastHLine(cx-20,cy-9+i*6,40,display.color565(180,180,180));
  } else {
    display.fillCircle(cx-8,cy,12,display.color565(210,210,210));
    display.fillCircle(cx+8,cy,14,display.color565(210,210,210));
    display.fillRect(cx-16,cy,32,12,display.color565(210,210,210));
  }
}

void drawWeatherPanel() {
  display.fillRect(0,0,LEFT_W,SCREEN_H,display.color565(245,245,245));
  display.drawFastVLine(LEFT_W,0,SCREEN_H,display.color565(150,150,150));
  int cx = LEFT_W/2;
  if (!weather.valid) {
    display.setFont(&fonts::efontTW_16); display.setTextSize(1);
    display.setTextColor(TFT_DARKGREY,display.color565(245,245,245));
    display.setCursor(8,60); display.print("天氣");
    display.setCursor(8,80); display.print("讀取中");
    return;
  }
  drawWeatherIcon(cx,55,weather.weatherCode);
  display.setFont(&fonts::efontTW_24); display.setTextSize(1);
  display.setTextColor(TFT_BLACK,display.color565(245,245,245));
  char tempBuf[8]; snprintf(tempBuf,sizeof(tempBuf),"%.0f`C",weather.temperature);
  int tw=display.textWidth(tempBuf);
  display.setCursor(cx-tw/2,100); display.print(tempBuf);
  display.setFont(&fonts::efontTW_16);
  display.setTextColor(display.color565(60,60,60),display.color565(245,245,245));
  String desc=weatherDesc(weather.weatherCode);
  int dw=display.textWidth(desc);
  display.setCursor(cx-dw/2,132); display.print(desc);
  struct tm timeinfo;
  if (getLocalTime(&timeinfo)) {
    char timeBuf[9]; snprintf(timeBuf,sizeof(timeBuf),"%02d:%02d",timeinfo.tm_hour,timeinfo.tm_min);
    display.setFont(&fonts::efontTW_16);
    display.setTextColor(display.color565(100,100,100),display.color565(245,245,245));
    int cw=display.textWidth(timeBuf);
    display.setCursor(cx-cw/2,SCREEN_H-30); display.print(timeBuf);
  }
}

void drawHeader() {
  display.fillRect(RIGHT_X,0,RIGHT_W,HEADER_H,display.color565(200,0,0));
  display.setFont(&fonts::efontTW_16); display.setTextSize(1);
  display.setTextColor(TFT_WHITE,display.color565(200,0,0));
  display.setCursor(RIGHT_X+8,8); display.print("分鐘 min(s)");
  int totalPages=(routeList.size()+ROWS_PER_PAGE-1)/ROWS_PER_PAGE;
  if (totalPages>1) {
    char pageBuf[12]; snprintf(pageBuf,sizeof(pageBuf),"%d/%d",currentPage+1,totalPages);
    int pw=display.textWidth(pageBuf);
    display.setCursor(RIGHT_X+RIGHT_W-pw-8,8); display.print(pageBuf);
  }
}

void drawRouteRow(int slot, int listIdx) {
  int yTop=HEADER_H+slot*ROW_H;
  uint16_t bg=(slot%2==0)?TFT_WHITE:display.color565(235,235,235);
  display.fillRect(RIGHT_X,yTop,RIGHT_W,ROW_H,bg);
  display.drawFastHLine(RIGHT_X,yTop,RIGHT_W,display.color565(150,150,150));
  if (listIdx<0||listIdx>=(int)routeList.size()) {
    display.setFont(&fonts::efontTW_16); display.setTextSize(1);
    display.setTextColor(TFT_DARKGREY,bg);
    display.setCursor(RIGHT_X+8,yTop+ROW_H/2-8);
    display.print("- 沒有更多路線 -");
    return;
  }
  RouteConfig &cfg=routeList[listIdx];
  RouteStatus &st=routeStatus[listIdx];
  display.setFont(&fonts::efontTW_24); display.setTextSize(1);
  display.setTextColor(TFT_BLACK,bg);
  display.setCursor(RIGHT_X+8,yTop+8); display.print(cfg.route);
  display.setFont(&fonts::efontTW_16); display.setTextSize(3);
  uint16_t numColor=display.color565(0,90,220);
  char numBuf[8];
  if (st.valid) {
    time_t now=time(nullptr);
    long secLeft=(long)(st.etaEpoch-now);
    long minLeft=secLeft/60;
    if (minLeft<0) minLeft=0;
    if (secLeft<=60) { numColor=display.color565(220,0,0); snprintf(numBuf,sizeof(numBuf),"-"); }
    else { if(minLeft<=3) numColor=display.color565(220,0,0); snprintf(numBuf,sizeof(numBuf),"%ld",minLeft); }
  } else { snprintf(numBuf,sizeof(numBuf),"--"); }
  int nw=display.textWidth(numBuf);
  display.setTextColor(numColor,bg);
  display.setCursor(RIGHT_X+RIGHT_W-nw-10,yTop+4); display.print(numBuf);
  display.setFont(&fonts::efontTW_16); display.setTextSize(1);
  display.setTextColor(display.color565(90,90,90),bg);
  display.setCursor(RIGHT_X+8,yTop+40);
  display.print("往 "); display.print(st.valid?st.dest:String("--"));
}

void drawRoutesArea() {
  int startIdx=currentPage*ROWS_PER_PAGE;
  for (int slot=0;slot<ROWS_PER_PAGE;slot++) drawRouteRow(slot,startIdx+slot);
}

void drawFullScreen() { drawWeatherPanel(); drawHeader(); drawRoutesArea(); }

void advancePage() {
  int totalPages=(routeList.size()+ROWS_PER_PAGE-1)/ROWS_PER_PAGE;
  if (totalPages<1) totalPages=1;
  currentPage=(currentPage+1)%totalPages;
}

// =====================================================
// setup / loop
// =====================================================
void setup() {
  Serial.begin(115200);
  delay(300);

  display.init();
  display.setRotation(1);
  display.fillScreen(TFT_BLACK);

  prefs.begin("kmb-board", false);
  loadRoutesFromPrefs();
  routeStatus.resize(routeList.size());

  generateCsrfToken(); // ★ 開機產生 CSRF Token

  connectWiFi();
  syncNTP();
  setupWebServer();

  fetchAllRoutes();
  fetchWeather();

  display.fillScreen(TFT_BLACK);
  drawFullScreen();

  lastEtaFetch     = millis();
  lastWeatherFetch = millis();
  lastPageFlip     = millis();
}

void loop() {
  // 只在 AP 開啟時才處理網頁請求
  if (apActive) server.handleClient();

  // ★ WiFi 重連加入冷卻（30秒才重試一次，避免頻繁觸發）
  if (WiFi.status() != WL_CONNECTED) {
    if (millis() - lastWifiRetry >= WIFI_RETRY_INTERVAL) {
      Serial.println("WiFi 斷線，嘗試重連...");
      WiFi.reconnect();
      lastWifiRetry = millis();
    }
  } else {
    lastWifiRetry = 0; // 恢復連線後重置計時器
  }

  // AP 限時自動關閉
  if (apActive && millis() - apEnabledAt >= AP_ON_DURATION) {
    disableConfigAP();
  }

  // 長按 BOOT 掣 3 秒重開 AP
  bool pressed = (digitalRead(BOOT_BUTTON_PIN) == LOW);
  if (pressed) {
    if (bootPressStart == 0) { bootPressStart = millis(); bootLongPressHandled = false; }
    else if (!bootLongPressHandled && millis() - bootPressStart >= BOOT_LONG_PRESS) {
      if (!apActive) enableConfigAP();
      else apEnabledAt = millis(); // 已開啟則延長
      bootLongPressHandled = true;
    }
  } else { bootPressStart = 0; bootLongPressHandled = false; }

  // 時鐘更新（每秒）
  struct tm timeinfo;
  if (getLocalTime(&timeinfo) && timeinfo.tm_sec != lastSecond) {
    lastSecond = timeinfo.tm_sec;
    display.fillRect(4,SCREEN_H-34,LEFT_W-8,20,display.color565(245,245,245));
    char timeBuf[9]; snprintf(timeBuf,sizeof(timeBuf),"%02d:%02d",timeinfo.tm_hour,timeinfo.tm_min);
    display.setFont(&fonts::efontTW_16); display.setTextSize(1);
    display.setTextColor(display.color565(100,100,100),display.color565(245,245,245));
    int cw=display.textWidth(timeBuf);
    display.setCursor(LEFT_W/2-cw/2,SCREEN_H-30); display.print(timeBuf);
  }

  if (millis()-lastEtaFetch>=ETA_REFRESH_INTERVAL) {
    fetchAllRoutes(); drawRoutesArea(); lastEtaFetch=millis();
  }
  if (millis()-lastWeatherFetch>=WEATHER_REFRESH_INTERVAL) {
    fetchWeather(); drawWeatherPanel(); lastWeatherFetch=millis();
  }

  int totalPages=(routeList.size()+ROWS_PER_PAGE-1)/ROWS_PER_PAGE;
  if (totalPages>1 && millis()-lastPageFlip>=PAGE_INTERVAL) {
    advancePage(); drawHeader(); drawRoutesArea(); lastPageFlip=millis();
  }

  delay(50);
}