//--------------------------------------------------------------
// File     : stm32_ub_usbdisk.h
//--------------------------------------------------------------

//--------------------------------------------------------------
#ifndef __STM32F4_UB_USBDISK_H
#define __STM32F4_UB_USBDISK_H

#define USB_PRESENT                                 ((uint8_t)0x01)
#define USB_NOT_PRESENT                             ((uint8_t)0x00)


//--------------------------------------------------------------
// Globale Funktionen
//--------------------------------------------------------------
void USBDisk_Init(void);
uint8_t USBDrive_CheckMedia(void);
int USB_disk_initialize(void);
int USB_disk_status(void);
int USB_disk_read(BYTE *buff, DWORD sector, BYTE count);
int USB_disk_write(const BYTE *buff, DWORD sector, BYTE count);
int USB_disk_ioctl(BYTE cmd, void *buff); 


//--------------------------------------------------------------
#endif // __STM32F4_UB_USBDISK_H
