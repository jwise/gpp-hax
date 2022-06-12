#include <stddef.h>
#include <stdarg.h>

#include "lpc177x_8x_pinsel.h"
#include "lpc177x_8x_clkpwr.h"
#include "lpc177x_8x_gpio.h"
#include "tusb.h"

#include "minilib.h"

extern void mdelay(int ms);

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
	mdelay(50);
	LPC_USB->HcControl = 0;
	LPC_USB->HcControlHeadED = 0;
	LPC_USB->HcBulkHeadED = 0;
	tuh_init(0);
}

void usb_poll() {
	tuh_task();
}

void USB_IRQHandler(void)
{
	PINSEL_ConfigPin(1, 31, 0);
	GPIO_SetDir(1, 1 << 31, 1);
	GPIO_OutputValue(1, 1 << 31, 1);
	printf("UsbIntSt %08x; OTGIntSt %08x; HcInterruptStatus %08x; HcInterruptEnable %08x\r\n", LPC_SC->USBIntSt, LPC_USB->OTGIntSt, LPC_USB->HcInterruptStatus, LPC_USB->HcInterruptEnable);
	putchar('!');
	tuh_int_handler(0);
	GPIO_OutputValue(1, 1 << 31, 0);
}

void tuh_mount_cb(uint8_t dev_addr)
{
  // application set-up
  printf("A device with address %d is mounted\r\n", dev_addr);
}

void tuh_umount_cb(uint8_t dev_addr)
{
  // application tear-down
  printf("A device with address %d is unmounted \r\n", dev_addr);
}

//--------------------------------------------------------------------+
// MACRO TYPEDEF CONSTANT ENUM DECLARATION
//--------------------------------------------------------------------+
static scsi_inquiry_resp_t inquiry_resp;

bool inquiry_complete_cb(uint8_t dev_addr, msc_cbw_t const* cbw, msc_csw_t const* csw)
{
  if (csw->status != 0)
  {
    printf("Inquiry failed\r\n");
    return false;
  }

  // Print out Vendor ID, Product ID and Rev
  printf("%8s %16s rev %4s\r\n", inquiry_resp.vendor_id, inquiry_resp.product_id, inquiry_resp.product_rev);

  // Get capacity of device
  uint32_t const block_count = tuh_msc_get_block_count(dev_addr, cbw->lun);
  uint32_t const block_size = tuh_msc_get_block_size(dev_addr, cbw->lun);

  printf("Disk Size: %lu MB\r\n", block_count / ((1024*1024)/block_size));
  printf("Block Count = %lu, Block Size: %lu\r\n", block_count, block_size);

  return true;
}

//------------- IMPLEMENTATION -------------//
void tuh_msc_mount_cb(uint8_t dev_addr)
{
  printf("A MassStorage device is mounted\r\n");

  uint8_t const lun = 0;
  tuh_msc_inquiry(dev_addr, lun, &inquiry_resp, inquiry_complete_cb);
//
//  //------------- file system (only 1 LUN support) -------------//
//  uint8_t phy_disk = dev_addr-1;
//  disk_initialize(phy_disk);
//
//  if ( disk_is_ready(phy_disk) )
//  {
//    if ( f_mount(phy_disk, &fatfs[phy_disk]) != FR_OK )
//    {
//      puts("mount failed");
//      return;
//    }
//
//    f_chdrive(phy_disk); // change to newly mounted drive
//    f_chdir("/"); // root as current dir
//
//    cli_init();
//  }
}

void tuh_msc_umount_cb(uint8_t dev_addr)
{
  (void) dev_addr;
  printf("A MassStorage device is unmounted\r\n");

//  uint8_t phy_disk = dev_addr-1;
//
//  f_mount(phy_disk, NULL); // unmount disk
//  disk_deinitialize(phy_disk);
//
//  if ( phy_disk == f_get_current_drive() )
//  { // active drive is unplugged --> change to other drive
//    for(uint8_t i=0; i<CFG_TUH_DEVICE_MAX; i++)
//    {
//      if ( disk_is_ready(i) )
//      {
//        f_chdrive(i);
//        cli_init(); // refractor, rename
//      }
//    }
//  }
}
