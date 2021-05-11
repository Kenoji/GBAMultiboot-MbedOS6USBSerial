#include "ThisThread.h"
#include "mbed.h"
#include "USBSerial.h"
#include "rom.h"
#include <cstdint>

SPI spi(D11,D12,D13);
USBSerial pc(false, 0x1f00, 0x2012, 0x0001);

void SYS_initialize();

#define GBA_LOOKINGFOR_TICKMS 100
#define GBA_CALL_LOOKINGFOR 0x00006202
#define GBA_RETURN_LOOKINGFOR 0x72026202
#define GBA_CALL_FOUNDGBA 0x00006202
#define GBA_CALL_RECOGNITIONOK 0x00006102
#define GBA_CALL_HEADERCOMPLETE 0x00006200
#define GBA_CALL_EXCHANGEINFO 0x00006202
#define GBA_CALL_SENDPALETTE 0x000063D1
#define GBA_CALL_CRCRESPONDCHECK 0x00000065
#define GBA_RETURN_CRCRESPONDCHECK 0x00750065
#define GBA_CALL_EOF 0x00000066

uint32_t encryptionSeed;
uint32_t gba_response = 0;

bool GBA_initialize(int);
void GBA_writeRom();
uint32_t GBA_encryption(uint32_t, uint32_t);
uint32_t GBA_calcCRC(uint32_t, uint32_t);
uint32_t GBA_transfer(uint32_t,bool);

int main(){
    DigitalOut led(PB_12);

    led = !led;//notify

    SYS_initialize();

    led = !led;//notify

    if(!GBA_initialize(10000)){
        pc.printf("\r\nGBA initialize timeout.\r\n");
        led = !led;
        return -1;
    }

    led = !led;//notify

    GBA_writeRom();

    led = !led;//notify

    //wait boot
    ThisThread::sleep_for(5s);
    pc.wait_ready();
    ThisThread::sleep_for(1s);
    pc.printf("Key bit is LT/RT/D/U/L/R/Str/Sel/B/A\r\n");
    pc.printf("AppStart\r\n");

    led = !led;//notify

    uint8_t c[4];
    int cIdx=0;
    while (true) {

        while(pc.readable()){
            for(cIdx=0;cIdx<4;cIdx++){
                pc.read(&c[cIdx], 1);
            }
            gba_response = GBA_transfer((c[2]<<24)+(c[3]<<16)+(240*c[1] + c[0]), false);
            c[0]=(gba_response)&0xFF;
            c[1]=(gba_response>>8)&0xFF;
            pc.write(c,2);
        }
        
        /*
        gba_response = GBA_transfer(0x0000, false);
        c[0]=(gba_response)&0xFF;
        c[1]=(gba_response>>8)&0xFF;
        pc.write(c,2);
        */
    }
}

void SYS_initialize(){
    //SPI
    spi.format(8,3);
    spi.frequency(1000000);
}

bool GBA_initialize(int timeoutMs){
    int timeoutCnt = timeoutMs;
    pc.printf("Lookingfor... \r\n");
    gba_response = GBA_transfer(GBA_CALL_LOOKINGFOR,false);
    while(gba_response != GBA_RETURN_LOOKINGFOR){
        ThisThread::sleep_for(100ms);
        gba_response = GBA_transfer(GBA_CALL_LOOKINGFOR,false);
        timeoutMs-=GBA_LOOKINGFOR_TICKMS;
        if(timeoutMs <= 0)return false;
        pc.printf(".");
    }
    ThisThread::sleep_for(100ms);
    pc.printf("FoundGBA... \r\n");
    gba_response = GBA_transfer(GBA_CALL_FOUNDGBA,false);
    pc.printf("RecognitionOK... \r\n");
    gba_response = GBA_transfer(GBA_CALL_RECOGNITIONOK,false);
    return true;
}
void GBA_writeRom() {

  // Send header
  for (int counter = 0; counter <= 0x5f; counter++) {
    uint32_t data = 0;
    /*
    for(int i=0;i<2;i++){
        uint8_t c;
        data=data<<8;
        pc.read(&c, 1);
        data+=(uint32_t)c;
    }
    */
    data += rom[counter];
    data &= 0x0000FFFF;
    gba_response = GBA_transfer(data, false);
    // pc.printf("ptr : %d data:%x\r\n",counter,data);
  }

  gba_response = GBA_transfer(GBA_CALL_HEADERCOMPLETE, false);
  pc.printf("Transfer of header data complete\r\n");

  gba_response = GBA_transfer(GBA_CALL_EXCHANGEINFO, false);
  pc.printf("Exchange master/slave info again\r\n");

  gba_response = GBA_transfer(GBA_CALL_SENDPALETTE, false);
  pc.printf("Send palette data\r\n");

  gba_response = GBA_transfer(GBA_CALL_SENDPALETTE, false);
  pc.printf("Send palette data, receive 0x73hh****\r\n");

  encryptionSeed = ((gba_response & 0x00ff0000) >> 8) + 0xffff00d1;
  uint32_t hh = ((gba_response & 0x00ff0000) >> 16) + 0xf;
  pc.printf("m:%x\r\nhh:%x\r\n", encryptionSeed, hh);

  gba_response = GBA_transfer(hh | 0x6400, false);
  pc.printf("Send handshake data\r\n");

  uint32_t romsize = (sizeof(rom) + 0xf) & 0xfffffff0;
  gba_response = GBA_transfer(((romsize - 0xC0) >> 2) - 0x34, false);
  pc.printf("romsize : %d\r\n", romsize);
  pc.printf("Send length info, receive seed 0x**cc****\r\n");

  uint32_t crc = 0x0000c387;
  uint32_t rr = (gba_response >> 16) & 0xff;
  pc.printf("Send encrypted data (takes too long to show it all!)\r\n");

  // Send body
  for (int counter = 0xC0; counter < romsize; counter += 4) {
    uint32_t data = 0;
    /*
    for(int i=0;i<2;i++){
        uint8_t c;
        data=data<<8;
        pc.read(&c, 1);
        data+=(uint32_t)c;
    }
    */
    data += (counter >= sizeof(rom)) ? (0) : (rom[counter / 2]);
    data += ((counter + 2) >= sizeof(rom)) ? (0) : (rom[counter / 2 + 1] << 16);
    uint32_t data2 = GBA_encryption(data, counter);
    // pc.printf("ptr : %d data:%x\r\n",counter,data);
    crc = GBA_calcCRC(data, crc);
    gba_response = GBA_transfer(data2, false);
  }

  while (GBA_transfer(GBA_CALL_CRCRESPONDCHECK, false) != GBA_RETURN_CRCRESPONDCHECK) {
    pc.printf("Wait for GBA to respond with CRC\r\n");
    ThisThread::sleep_for(100ms);
  }
  pc.printf("GBA ready with CRC\r\n");

  gba_response = GBA_transfer(GBA_CALL_EOF, false);

  pc.printf("Let's exchange CRC!\r\n");
  uint32_t crctemp = ((((gba_response & 0xFF00) + rr) << 8) | 0xFFFF0000) + hh;
  crc = GBA_calcCRC(crctemp, crc);
  gba_response = GBA_transfer(crc, false);
  pc.printf("CRC is: %x\r\n", crc);
  pc.printf(" Actual: %x\r\n", gba_response);
}
uint32_t GBA_calcCRC(uint32_t data, uint32_t crc) {
  int bit;
  for (bit = 0; bit < 32; bit++)
  {
    uint32_t tmp = crc ^ data;
    crc >>= 1;
    data >>= 1;
    if (tmp & 0x01)
      crc ^= 0xc37b;
  }
  return crc;
}
uint32_t GBA_encryption(uint32_t data, uint32_t ptr){
  ptr = ~(ptr + 0x02000000) + 1;
  encryptionSeed = (encryptionSeed * 0x6F646573) + 1;

  data = (encryptionSeed ^ data) ^ (ptr ^ 0x43202F2F);
  return data;
}
uint32_t GBA_transfer(uint32_t data,bool isDebug){
    char buf[4];
    uint32_t ret = 0;
    buf[0] = data >> 24;
    buf[1] = data >> 16;
    buf[2] = data >> 8;
    buf[3] = data;
    spi.write(buf,4,buf,4);
    for(int i = 0;i < 4; i++){
        ret |= (uint32_t)buf[i] << ((3 - i) * 8);
    }
    if(isDebug){
        pc.printf("send : %x back : %x \r\n",data,ret);
    }
    return ret;
}