#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/printk.h>
#include <linux/proc_fs.h>
#include <asm/current.h>
#include <linux/uaccess.h>
#include <linux/sched/signal.h> 
#include <linux/sched.h>

#define procfs_name "Mythread_info"
#define BUFSIZE  1024
char buf[BUFSIZE]; //kernel buffer

static ssize_t Mywrite(struct file *fileptr, const char __user *ubuf, size_t buffer_len, loff_t *offset){
    char kbuf[64];
    size_t actual_len = buffer_len > 63 ? 63 : buffer_len;

    // 將資料從 User space 複製到 Kernel space
    if (copy_from_user(kbuf, ubuf, actual_len)) {
        return -EFAULT;
    }
    
    kbuf[actual_len] = '\0'; // 確保字串結尾安全
    
    // 使用 pr_info 或 printk 將收到的訊息印在 dmesg 中
    pr_info("Kernel received: %s\n", kbuf);

    return buffer_len; // 回傳寫入長度，告訴系統寫入成功
}


static ssize_t Myread(struct file *fileptr, char __user *ubuf, size_t buffer_len, loff_t *offset){
    struct task_struct *thread;
    int len = 0;
    static char local_buf[BUFSIZE]; // 使用 static 避免 Stack size 警告

    if (*offset > 0) return 0;

    // 遍歷當前行程中的執行緒
    for_each_thread(current, thread) {
        // 只有當 TID (thread->pid) 等於發起請求的執行緒時才輸出
        // 或者根據你的 Lab 要求，輸出該行程內所有執行緒
        if (thread->pid == current->pid) { 
            len += snprintf(local_buf + len, BUFSIZE - len, 
                            "PID: %d, TID: %d, time: %llu\n", 
                            thread->tgid, thread->pid, 
                            (unsigned long long)(thread->utime / 100 / 1000));
        }
    }

    if (copy_to_user(ubuf, local_buf, len)) {
        return -EFAULT;
    }

    *offset = len;
    return len;
}

static struct proc_ops Myops = {
    .proc_read = Myread,
    .proc_write = Mywrite,
};

static int My_Kernel_Init(void){
    proc_create(procfs_name, 0644, NULL, &Myops);   
    pr_info("My kernel says Hi");
    return 0;
}

static void My_Kernel_Exit(void){
    remove_proc_entry(procfs_name, NULL);
    pr_info("My kernel says GOODBYE");
}

module_init(My_Kernel_Init);
module_exit(My_Kernel_Exit);

MODULE_LICENSE("GPL");