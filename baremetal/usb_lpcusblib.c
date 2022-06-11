#include <stddef.h>
#include <stdarg.h>
#include <string.h>

#include "lpc177x_8x_pinsel.h"
#include "lpc177x_8x_clkpwr.h"
#include "lpc177x_8x_gpio.h"

#include "minilib.h"

#include "./lpcusblib/Drivers/USB/USB.h"

extern void mdelay(int ms);

static USB_ClassInfo_MS_Host_t FlashDisk_MS_Interface = {
	.Config = {
		.DataINPipeNumber       = 1,
		.DataINPipeDoubleBank   = false,

		.DataOUTPipeNumber      = 2,
		.DataOUTPipeDoubleBank  = false,
		.PortNumber = 0,
	},
};


void usb_setup() {
	SysTick_Config(SystemCoreClock / 1000);
	CLKPWR_ConfigPPWR(CLKPWR_PCONP_PCUSB, ENABLE);
	LPC_USB->OTGClkCtrl = 0x19; /* AHB_CLK | HOST_CLK | OTG_CLK */
	while ((LPC_USB->OTGClkSt & 0x19) != 0x19)
		;
	LPC_USB->OTGStCtrl = 1; /* U1 = U2 = host */
	PINSEL_ConfigPin(0, 29, 1);
	PINSEL_ConfigPin(0, 30, 1);
	puts("starting stack...\r\n");
	__enable_irq();
	USB_Init(0, USB_MODE_Host);
	puts("stack is alive\r\n");
}

void usb_poll() {
}

extern void HcdIrqHandler(uint8_t HostID);

void USB_IRQHandler(void)
{
	PINSEL_ConfigPin(1, 31, 0);
	GPIO_SetDir(1, 1 << 31, 1);
	GPIO_OutputValue(1, 1 << 31, 1);
	printf("pre:  UsbIntSt %08x; HcInterruptStatus %08x\r\n", LPC_SC->USBIntSt, LPC_USB->HcInterruptStatus);
	HcdIrqHandler(0);
	printf("post: UsbIntSt %08x; HcInterruptStatus %08x\r\n", LPC_SC->USBIntSt, LPC_USB->HcInterruptStatus);
	GPIO_OutputValue(1, 1 << 31, 0);
}


void HAL_USBInit(uint8_t corenum)
{
	/* Enable PLL1 for 48MHz output */
#if 0
	Chip_Clock_EnablePLL(SYSCTL_USB_PLL, SYSCTL_PLL_ENABLE);
	while ((Chip_Clock_GetPLLStatus(SYSCTL_USB_PLL) & SYSCTL_PLLSTS_LOCKED) == 0);
	
	LPC_SYSCTL->PCONP |= (1UL << 31);					/* USB PCLK -> enable USB Per.*/
#endif
}

void HAL_USBDeInit(uint8_t corenum, uint8_t mode)
{
	NVIC_DisableIRQ(USB_IRQn);													/* disable USB interrupt */
#if 0
	LPC_SYSCTL->PCONP &= (~(1UL << 31));								/* disable USB Per.      */	
	Chip_IOCON_PinMux(LPC_IOCON, 0, 29, IOCON_MODE_INACT, IOCON_FUNC0);	/* P0.29 D+, P0.30 D- reset to GPIO function */
	Chip_IOCON_PinMux(LPC_IOCON, 0, 30, IOCON_MODE_INACT, IOCON_FUNC0);
	/* Disable PLL1 to save power */
	Chip_Clock_DisablePLL(SYSCTL_USB_PLL, SYSCTL_PLL_ENABLE);
#endif
}

void HAL_EnableUSBInterrupt(uint8_t corenum)
{
	NVIC_EnableIRQ(USB_IRQn);					/* enable USB interrupt */
}

void HAL_DisableUSBInterrupt(uint8_t corenum)
{
	NVIC_DisableIRQ(USB_IRQn);					/* enable USB interrupt */
}

void HAL_USBConnect(uint8_t corenum, uint32_t con)
{
}

/** Event handler for the USB_DeviceAttached event. This indicates that a device has been attached to the host, and
 *  starts the library USB task to begin the enumeration and USB management process.
 */
void EVENT_USB_Host_DeviceAttached(const uint8_t corenum)
{
	printf(("Device Attached on port %d\r\n"), corenum);
}

/** Event handler for the USB_DeviceUnattached event. This indicates that a device has been removed from the host, and
 *  stops the library USB task management process.
 */
void EVENT_USB_Host_DeviceUnattached(const uint8_t corenum)
{
	printf(("\r\nDevice Unattached on port %d\r\n"), corenum);
}

/** Event handler for the USB_DeviceEnumerationComplete event. This indicates that a device has been successfully
 *  enumerated by the host and is now ready to be used by the application.
 */
void EVENT_USB_Host_DeviceEnumerationComplete(const uint8_t corenum)
{
	uint16_t ConfigDescriptorSize;
	uint8_t  ConfigDescriptorData[512];
	printf("device enumeration complete\r\n");

	if (USB_Host_GetDeviceConfigDescriptor(corenum, 1, &ConfigDescriptorSize, ConfigDescriptorData,
										   sizeof(ConfigDescriptorData)) != HOST_GETCONFIG_Successful) {
		printf("Error Retrieving Configuration Descriptor.\r\n");
		return;
	}

	FlashDisk_MS_Interface.Config.PortNumber = corenum;
	if (MS_Host_ConfigurePipes(&FlashDisk_MS_Interface,
							   ConfigDescriptorSize, ConfigDescriptorData) != MS_ENUMERROR_NoError) {
		printf("Attached Device Not a Valid Mass Storage Device.\r\n");
		return;
	}

	if (USB_Host_SetDeviceConfiguration(FlashDisk_MS_Interface.Config.PortNumber, 1) != HOST_SENDCONTROL_Successful) {
		printf("Error Setting Device Configuration.\r\n");
		return;
	}

	uint8_t MaxLUNIndex;
	if (MS_Host_GetMaxLUN(&FlashDisk_MS_Interface, &MaxLUNIndex)) {
		printf("Error retrieving max LUN index.\r\n");
		USB_Host_SetDeviceConfiguration(FlashDisk_MS_Interface.Config.PortNumber, 0);
		return;
	}

	printf(("Total LUNs: %d - Using first LUN in device.\r\n"), (MaxLUNIndex + 1));

	if (MS_Host_ResetMSInterface(&FlashDisk_MS_Interface)) {
		printf("Error resetting Mass Storage interface.\r\n");
		USB_Host_SetDeviceConfiguration(FlashDisk_MS_Interface.Config.PortNumber, 0);
		return;
	}

	SCSI_Request_Sense_Response_t SenseData;
	if (MS_Host_RequestSense(&FlashDisk_MS_Interface, 0, &SenseData) != 0) {
		printf("Error retrieving device sense.\r\n");
		USB_Host_SetDeviceConfiguration(FlashDisk_MS_Interface.Config.PortNumber, 0);
		return;
	}

	//  if (MS_Host_PreventAllowMediumRemoval(&FlashDisk_MS_Interface, 0, true)) {
	//      printf("Error setting Prevent Device Removal bit.\r\n");
	//      USB_Host_SetDeviceConfiguration(FlashDisk_MS_Interface.Config.PortNumber, 0);
	//      return;
	//  }

	SCSI_Inquiry_Response_t InquiryData;
	if (MS_Host_GetInquiryData(&FlashDisk_MS_Interface, 0, &InquiryData)) {
		printf("Error retrieving device Inquiry data.\r\n");
		USB_Host_SetDeviceConfiguration(FlashDisk_MS_Interface.Config.PortNumber, 0);
		return;
	}

	printf("Vendor \"%.8s\", Product \"%.16s\"\r\n", InquiryData.VendorID, InquiryData.ProductID);

	printf("Mass Storage Device Enumerated.\r\n");
}

/** Event handler for the USB_HostError event. This indicates that a hardware error occurred while in host mode. */
void EVENT_USB_Host_HostError(const uint8_t corenum, const uint8_t ErrorCode)
{
	USB_Disable(corenum, USB_MODE_Host);

	printf(("Host Mode Error\r\n"
			  " -- Error port %d\r\n"
			  " -- Error Code %d\r\n" ), corenum, ErrorCode);

	for (;; ) {}
}

/** Event handler for the USB_DeviceEnumerationFailed event. This indicates that a problem occurred while
 *  enumerating an attached USB device.
 */
void EVENT_USB_Host_DeviceEnumerationFailed(const uint8_t corenum,
											const uint8_t ErrorCode,
											const uint8_t SubErrorCode)
{
	printf(("Dev Enum Error\r\n"
			  " -- Error port %d\r\n"
			  " -- Error Code %d\r\n"
			  " -- Sub Error Code %d\r\n"
			  " -- In State %d\r\n" ),
			 corenum, ErrorCode, SubErrorCode, USB_HostState[corenum]);

}
