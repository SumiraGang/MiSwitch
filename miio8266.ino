
//String on_text = "{\"id\": 1, \"method\": \"set_power\", \"params\": [\"on\"]}";

#include <ESP8266WiFi.h> //ESP8266基本网络功能
#include "EZMD5.h"
#include "AES.h"

#include <WiFiUdp.h> 
#include <Bounce2.h>

const char *ssid = "";     //网络名称
const char *password = ""; //网络密码WiFiUDP Udp;
unsigned int localPort = 2333; 
const byte switch_ip[4] = {192, 168, 3, 6};
unsigned int switch_port = 54321;

int BUTTON = 14;
int REDBUTTON = 5;
int if_on = 0;
int val = LOW;
int old_val = LOW;
int redv = LOW;
int old_red = LOW;

byte hello[32];
byte on_str[96];
byte off_str[96];
byte bf[256];
byte keyiv[32];
byte token[16];
byte iv[16];

static char* md5str;

AES aes;

byte on_aes[] = {
  0x96, 0x7A, 0x1D, 0xEF, 0xB9, 0x8A, 0x1D, 0x4C, 0xF1, 0xC3, 0x01, 0xD8, 0xC8, 0xE5, 0xFB, 0xE1, 
  0x2D, 0x76, 0xC7, 0x4B, 0xED, 0x6A, 0xB4, 0x9B, 0xF0, 0x10, 0x6F, 0x56, 0x37, 0xEE, 0x5D, 0x55, 
  0xCF, 0x32, 0x35, 0x0B, 0xED, 0xEF, 0x07, 0xCF, 0xF7, 0xC5, 0xA0, 0x9D, 0x70, 0x87, 0x05, 0x6C, 
  0xBD, 0xC6, 0x47, 0x71, 0x2F, 0x4F, 0xB0, 0xB0, 0x74, 0x9D, 0x86, 0x9F, 0xB7, 0x55, 0x99, 0xCC};

byte off_aes[] = {
  0x96, 0x7A, 0x1D, 0xEF, 0xB9, 0x8A, 0x1D, 0x4C, 0xF1, 0xC3, 0x01, 0xD8, 0xC8, 0xE5, 0xFB, 0xE1, 
  0x2D, 0x76, 0xC7, 0x4B, 0xED, 0x6A, 0xB4, 0x9B, 0xF0, 0x10, 0x6F, 0x56, 0x37, 0xEE, 0x5D, 0x55, 
  0xE8, 0x2E, 0xB3, 0x5C, 0x9F, 0xA0, 0xE2, 0x5F, 0x53, 0xFE, 0xC9, 0x9A, 0x12, 0x68, 0x79, 0x19, 
  0x9E, 0x24, 0xF2, 0x3F, 0xB7, 0x14, 0xEC, 0x25, 0x7C, 0xAC, 0x75, 0x33, 0x26, 0x87, 0x04, 0x9F};

WiFiUDP Udp;
Bounce debouncer = Bounce();
Bounce reddeb = Bounce();

void init_msg(){
  hello[0] = 0x21;
  hello[1] = 0x31;
  hello[2] = 0;
  hello[3] = 0x20;
  memset(&hello[4], 0xff, 28);

  memcpy(on_str, hello, 3);
  on_str[3] = 0x60;
  memset(&on_str[4], 0, 28);
  memcpy(off_str, on_str, 32);
  memcpy(&on_str[32], on_aes, 64);
  memcpy(&off_str[32], off_aes, 64);  
}

int miio_switch(byte* str){
  int i;
  
  Udp.beginPacket(switch_ip, switch_port); //准备发送数据
  Udp.write((const uint8_t*)hello, 32); //复制数据到发送缓存
  Udp.endPacket();
  
  for(i = 0; i<100; i++){
    int packetSize = Udp.parsePacket();
    if(packetSize){
      Udp.read(bf, 32);
      break;
    }
    delay(100);
  }


  if(i == 100){
    return -1;
  }

  memcpy(&str[8], &bf[8], 24);
  memcpy(token, &bf[16], 16);

  MD5::my_hash(keyiv, (char*)token, 16);
  memcpy(keyiv+16, token, 16);
  MD5::my_hash(keyiv+16, (char*)keyiv, 32);

  MD5::my_hash(&str[16], (char*)str, 96);
  Udp.beginPacket(switch_ip, switch_port);
  Udp.write((const uint8_t*)str, 96);
  Udp.endPacket();

  md5str = MD5::make_digest(str, 96);
  Serial.println("send:");
  Serial.println(md5str);
  free(md5str);
  int packetSize = 0;
  
  for(i = 0; i<100; i++){
    packetSize = Udp.parsePacket();
    if(packetSize){
      Udp.read(bf, 256);
      break;
    }
    delay(100);
  }

  Serial.println("packsize");
  Serial.println(packetSize);

  byte decrypted[64];
  memcpy(iv, keyiv+16, 16);
  aes.setPadMode((paddingMode)0);
  int dl = aes.do_aes_decrypt(bf+32, packetSize-32, decrypted, keyiv, 16, iv);
  decrypted[dl] = 0;

//  md5str = MD5::make_digest(bf, 96);
//  Serial.println("return:");
//  Serial.println(md5str);
//  free(md5str);
  Serial.println("return:");
  Serial.println((char*) decrypted);

  if(i == 100){
    return -1;
  }

  return 1;
}

void setup() {
  if_on = 0;
  
  pinMode(LED_BUILTIN, OUTPUT);
  pinMode(BUTTON, INPUT);
  pinMode(REDBUTTON, INPUT);
  digitalWrite(LED_BUILTIN, HIGH);
  
  debouncer.attach(BUTTON);
  debouncer.interval(5);

  reddeb.attach(REDBUTTON);
  reddeb.interval(5);

  //initialize serial
  Serial.begin(9600);
  Serial.println();

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);
  while (!WiFi.isConnected())
  {
    delay(500);
    Serial.print(".");
  }
  Serial.println("Connected");
  Serial.print("IP Address:");
  Serial.println(WiFi.localIP());
  init_msg();
  
  //give it a second
  delay(500);
  Serial.printf("UDP server on port %d\n", localPort);
  Udp.begin(localPort);

  digitalWrite(LED_BUILTIN, LOW);
  delay(100);
  digitalWrite(LED_BUILTIN, HIGH);
  delay(100);
  digitalWrite(LED_BUILTIN, LOW);
  delay(100);
  digitalWrite(LED_BUILTIN, HIGH);
  delay(100);
}

void loop() {
  debouncer.update();
  
  reddeb.update();
  val = debouncer.read();
  redv = reddeb.read();

  if((val==LOW)&&(old_val==HIGH)){
    Serial.println("blue on");
    if(miio_switch(on_str)>0){
      digitalWrite(LED_BUILTIN, LOW);}
  }

  if((redv==LOW)&&(old_red==HIGH)){
    
    Serial.println("red on");
    if(miio_switch(off_str)>0){
      digitalWrite(LED_BUILTIN, HIGH);}
  }

  old_val = val;
  old_red = redv;
  
//  if((val==LOW)&&(old_val==HIGH)){
//    if(if_on){
//      if(miio_switch(off_str)>0){
//        if_on = 0;
//        digitalWrite(LED_BUILTIN, HIGH);}
//    }else{
//      if(miio_switch(on_str)>0){
//        if_on = 1;
//        digitalWrite(LED_BUILTIN, LOW);}
//    }
//  }
}
