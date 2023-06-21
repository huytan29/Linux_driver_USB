#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/usb.h>
#include <linux/scatterlist.h>
#include <crypto/skcipher.h>

#define ENCRYPT_KEY_SIZE 16

static struct usb_device *usb_dev = NULL;
static struct crypto_skcipher *tfm;
static struct skcipher_request *crypto_req;
static u8 encrypt_key[ENCRYPT_KEY_SIZE] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                                           0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};

static int usb_driver_probe(struct usb_interface *interface, const struct usb_device_id *id)
{
    // Get USB device information
    usb_dev = interface_to_usbdev(interface);

    // Initialize cipher request
    tfm = crypto_alloc_skcipher("ecb-aes-aesni", 0, 0);
    if (IS_ERR(tfm)) {
        printk(KERN_ERR "Failed to allocate cipher handle\n");
        return PTR_ERR(tfm);
    }

    crypto_req = skcipher_request_alloc(tfm, GFP_KERNEL);
    if (!crypto_req) {
        printk(KERN_ERR "Failed to allocate cipher request\n");
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }

    // Set encryption key
    int ret = crypto_skcipher_setkey(tfm, encrypt_key, ENCRYPT_KEY_SIZE);
    if (ret) {
        printk(KERN_ERR "Failed to set encryption key\n");
        skcipher_request_free(crypto_req);
        crypto_free_skcipher(tfm);
        return ret;
    }

    // Encrypt data during copy
    struct usb_host_endpoint *endpoint = &interface->cur_altsetting->endpoint[0];
    struct urb *urb = usb_alloc_urb(0, GFP_KERNEL);
    if (!urb) {
        printk(KERN_ERR "Failed to allocate URB\n");
        skcipher_request_free(crypto_req);
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }

    unsigned char *buffer = kmalloc(endpoint->desc.wMaxPacketSize, GFP_KERNEL);
    if (!buffer) {
        printk(KERN_ERR "Failed to allocate buffer\n");
        usb_free_urb(urb);
        skcipher_request_free(crypto_req);
        crypto_free_skcipher(tfm);
        return -ENOMEM;
    }

    struct scatterlist sg_input[1];
    sg_init_table(sg_input, ARRAY_SIZE(sg_input));
    sg_set_buf(&sg_input[0], buffer, endpoint->desc.wMaxPacketSize);

    struct scatterlist sg_output[1];
    sg_init_table(sg_output, ARRAY_SIZE(sg_output));
    sg_set_buf(&sg_output[0], buffer, endpoint->desc.wMaxPacketSize);

    skcipher_request_set_crypt(crypto_req, sg_input, sg_output, endpoint->desc.wMaxPacketSize, NULL);

    usb_fill_bulk_urb(urb, usb_dev, usb_rcvbulkpipe(usb_dev, usb_endpoint_num(&endpoint->desc)),
                      sg_virt(&sg_input[0]), endpoint->desc.wMaxPacketSize, NULL);

    usb_anchor_urb(urb, &interface->urb_anchor);

    ret = usb_submit_urb(urb, GFP_KERNEL);
    if (ret) {
        printk(KERN_ERR "Failed to submit URB\n");
        usb_unanchor_urb(urb);
        usb_kill_urb(urb);
    }

    kfree(buffer);

    return 0;
}

static void usb_driver_disconnect(struct usb_interface *interface)
{
    struct urb *urb;

    usb_lock_device(interface_to_usbdev(interface));
    usb_for_each_urb(interface_to_usbdev(interface), urb) {
        usb_unanchor_urb(urb);
        usb_kill_urb(urb);
    }
    usb_unlock_device(interface_to_usbdev(interface));

    usb_free_urb(interface->urb_anchor.next);
    skcipher_request_free(crypto_req);
    crypto_free_skcipher(tfm);
}

static struct usb_driver usb_driver = {
    .name = "usb_driver_huytan",
    .probe = usb_driver_probe,
    .disconnect = usb_driver_disconnect,
};

static int __init usb_driver_init(void)
{
    int result;

    result = usb_register(&usb_driver);
    if (result < 0) {
        return result;
    }
    return 0;
}

static void __exit usb_driver_exit(void)
{
    usb_deregister(&usb_driver);
}

module_init(usb_driver_init);
module_exit(usb_driver_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("USB Driver Example");
