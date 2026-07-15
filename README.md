# esp32c3SuperMini_KMB
想用一粒細小的esp32板去處這個專案。
TFT mon 用的是2.4吋 240X320 driver IC ST7789
駁線如圖

<img width="745" height="317" alt="tftC3" src="https://github.com/user-attachments/assets/7aa66ac7-cfdd-4f86-b5ce-74bb0c983d2f" />

ESP32 C3pro super mini

<img width="306" height="408" alt="20260715_155006" src="https://github.com/user-attachments/assets/4d82eeba-1bd3-45bb-b0ee-ca164c18b0ed" />
焊上針板
<img width="408" height="306" alt="20260715_165256" src="https://github.com/user-attachments/assets/7dd40c6c-bd9d-44f3-8e92-263f1c2aec56" />
<img width="408" height="306" alt="20260715_170016" src="https://github.com/user-attachments/assets/d86bdaa3-e462-4bc1-9c4e-e3b27ff605fa" />
<img width="408" height="306" alt="20260715_170001" src="https://github.com/user-attachments/assets/7841ae88-440f-48c6-ad61-816e85e3b935" />
利用wifimanager library 功能，提供一個設定用熱點。第一次通電在沒有wifi 連線下，會開啟一個ESP32-KMB-Setup 熱點，連線後，手動打開瀏覽器連 192.168.4.1，就可以選擇可以連接的WIFI SSID 及輸入密碼。
為了不用每次都通過編輯程式去修改路線，當成本連上WIFI 之後，會見到一個 ESP-BusConfig 的SSID。，在程序中的見預設密碼，可以自行修改。

連上ESP-BusConfig 後，手動打開瀏覽器連 192.168.4.1，又會進入一個設定頁面。為提高安全，請在程式燒錄前，修改一下 WEB_USER 以及 WEB_PASS 兩個參數。
為了避免AP ( ESP-BusConfig) 長期曝露 ，要開啟 ESP-BusConfig 要長按 BOOT 才重開，限時 10 分鐘
進入後就可以通過輸入巴士站的stop_ID，路線，來修改路線。
<img width="1080" height="2079" alt="Screenshot_20260715_173325_Chrome" src="https://github.com/user-attachments/assets/c4c53c97-4c9a-4720-b229-3eedca4a751e" />

程式是通過claude AI 處理。。。
