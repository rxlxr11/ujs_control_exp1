import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
import struct
import serial
import logging


global regs
global modbus

def crc16(string):
    data = bytearray.fromhex(string)
    logging.info(type(data))
    crc = 0xFFFF
    for pos in data:
        crc ^= pos
        for i in range(8):
            if ((crc & 1) != 0):
                crc >>= 1
                crc ^= 0xA001
            else:
                crc >>= 1
    return ((crc & 0xff) << 8) + (crc >> 8)


def float_to_hex(f):
    # 将浮点数转换为字节串
    b = struct.pack('!f', f)
    # 将字节串转换为十六进制字符串
    hex_str = ''.join(format(byte, '02X') for byte in b)
    return hex_str


def hex_to_float(hex_str):
    # 将十六进制字符串转换为字节串
    b = bytes.fromhex(hex_str)
    if len(b) != 4:
        raise ValueError("Hexadecimal string must be 4 characters long")
    # 使用unpack函数将字节串转换为浮点数
    f = struct.unpack('>f', b)[0]
    return f


class Modbus_Frame:

    def __init__(self):
        self.send = ''
        self.receive = ''
    # 02 03 00 00 00 03，其中02是设备地址，03是读寄存器命令，00 00是寄存器起始地址，而00 03是寄存器数量
    # 02 06 00 03 00 FE，其中 02 是设备地址，06 是设置单个寄存器命令，00 03 是寄存器起始地址，而00 FE 是设置的数值
    def cmd_frame(self, addr, cmd, start, count):
        hex_numbers = []
        hex_numbers.append("{:02x}".format(addr))  # 将地址转换为两位十六进制格式
        hex_numbers.append("{:02x}".format(cmd))  # 将寄存器数量转换为两位十六进制格式
        hex_numbers.append("{:04x}".format(start))  # 将起始地址转换为四位十六进制格式
        hex_numbers.append("{:04x}".format(count))  # 将数据数量转换为四位十六进制格式
        hex_numbers.append("{:04x}".format(crc16("".join(str(hex_num) for hex_num in hex_numbers))))  # 将数据数量转换为四位十六进制格式
        hex_str = ''.join(hex_numbers)
        self.send = hex_str
        print("send", self.send)
        byte_frame = b"".join(bytes.fromhex(hex_num) for hex_num in hex_numbers)  # 拼接成字节串
        return byte_frame

    def analyse_frame(self, frame):
        data = []
        data.append('ok')
        self.receive = ''.join([hex(byte)[2:].zfill(2) for byte in frame])
        print("receive", self.receive)
        hex_list = [frame[i:i+1] for i in range(0, len(frame), 1)]
        hex_strings = [byte.hex() for byte in hex_list]
        origin_addr = int(hex_strings[0], 16)
        cmd = int(hex_strings[1], 16)
        if cmd == 3:
            length = int(hex_strings[2], 16)
            for i in range(3, 3 + length, 2):
                # 在这里执行循环体的操作
                data.append(int(hex_strings[i]+hex_strings[i+1], 16))
        elif cmd == 6:
            if self.receive != self.send:
                data[0] = 'error'
        else:
            data[0] = 'error'
        return data


class GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("设备控制")

        # # 数组数据
        # self.data = regs  # 示例数组，包含 10 个元素
        #
        # # 表格
        # self.table = ttk.Treeview(self.root)
        # self.table["columns"] = ("Value")
        # self.table.heading("#0", text="Index")
        # self.table.heading("Value", text="Value")
        # self.table.grid(row=0, column=0, columnspan=2, padx=10, pady=10)
        # self.update_table()

        # 设备地址
        self.device_label = tk.Label(self.root, text="设备地址:")
        self.device_label.grid(row=1, column=0, padx=10, pady=5)
        self.device_entry = tk.Entry(self.root)
        self.device_entry.grid(row=1, column=1, padx=10, pady=5)

        # 寄存器地址
        self.reg_label = tk.Label(self.root, text="寄存器地址:")
        self.reg_label.grid(row=2, column=0, padx=10, pady=5)
        self.reg_entry = tk.Entry(self.root)
        self.reg_entry.grid(row=2, column=1, padx=10, pady=5)

        # 寄存器数据
        self.reg_data_label = tk.Label(self.root, text="寄存器值:")
        self.reg_data_label.grid(row=3, column=0, padx=10, pady=5)
        self.reg_data_entry = tk.Entry(self.root)
        self.reg_data_entry.grid(row=3, column=1, padx=10, pady=5)

        # 数据类型选择器
        self.data_type_label = tk.Label(self.root, text="数据类型:")
        self.data_type_label.grid(row=4, column=0, padx=10, pady=5)
        self.data_type_var = tk.StringVar(value="整数")
        self.data_type_combobox = ttk.Combobox(self.root, textvariable=self.data_type_var, values=["整数", "浮点数"])
        self.data_type_combobox.grid(row=4, column=1, padx=10, pady=5)

        # 读取和写入按钮
        self.read_button = tk.Button(self.root, text="读取", command=self.read_data)
        self.read_button.grid(row=5, column=0, padx=10, pady=5)
        self.write_button = tk.Button(self.root, text="写入", command=self.write_data)
        self.write_button.grid(row=5, column=1, padx=20, pady=5)

    # def update_table(self):
    #     # 清空表格
    #     for item in self.table.get_children():
    #         self.table.delete(item)
    #     # 填充表格
    #     for i, value in enumerate(self.data):
    #         self.table.insert("", "end", text=str(i), values=(str(value)))

    def read_data(self):
        device_value = self.device_entry.get()
        reg_value = self.reg_entry.get()

        if device_value and reg_value:
            try:
                device_address = int(device_value)
                reg_address = int(reg_value)
                if self.data_type_combobox.get() == '整数':
                    message = modbus.cmd_frame(device_address, 3, reg_address, 1)
                    my_serial.write(message)
                    res = my_serial.read(7)
                    if res:
                        data = modbus.analyse_frame(res)
                        if data[0] == 'ok':
                            self.reg_data_entry.delete(0, 'end')  # 清空输入框
                            self.reg_data_entry.insert(0, data[1])  # 写入新的文本
                            messagebox.showinfo('success', data[1])  # 显示消息
                        else:
                            messagebox.showerror("Error", "error receive")
                    else:
                        messagebox.showerror("Error", "cannot receive")
                else:
                    message = modbus.cmd_frame(device_address, 3, reg_address, 2)
                    my_serial.write(message)
                    res = my_serial.read(9)
                    if res:
                        data = modbus.analyse_frame(res)
                        if data[0] == 'ok':
                            self.reg_data_entry.delete(0, 'end')  # 清空输入框
                            f_data = hex_to_float("{:02x}".format(data[1])+"{:02x}".format(data[2]))
                            self.reg_data_entry.insert(0, f_data)  # 写入新的文本
                            messagebox.showinfo('success', f_data)  # 显示消息
                        else:
                            messagebox.showerror("Error", "error receive")
                    else:
                        messagebox.showerror("Error", "cannot receive")

            except ValueError:
                messagebox.showerror("Error", "Invalid hexadecimal value")
        else:
            messagebox.showerror("Error", "Please enter device address and register address")


    def write_data(self):
        # 在这里实现写入数据的逻辑
        device_value = self.device_entry.get()
        reg_value = self.reg_entry.get()
        data_value = self.reg_data_entry.get()
        if device_value and reg_value and data_value:
            try:
                device_address = int(device_value)
                reg_address = int(reg_value)
                message = modbus.cmd_frame(device_address, 6, reg_address, int(data_value))
                my_serial.write(message)
                res = my_serial.read(8)
                if res:
                    data = modbus.analyse_frame(res)
                    if data[0] == 'ok':
                        messagebox.showinfo('success')  # 显示消息
                    else:
                        messagebox.showerror("Error", "error receive")
                else:
                    messagebox.showerror("Error", "cannot receive")
            except ValueError:
                messagebox.showerror("Error", "Invalid hexadecimal value")
        else:
            messagebox.showerror("Error", "Please enter device address and register address")



modbus = Modbus_Frame()
if __name__ == "__main__":
    # print(hex_to_float('0102'))
    my_serial = serial.Serial(port='COM2', baudrate=9600, timeout= 5)
    root = tk.Tk()
    gui = GUI(root)
    root.mainloop()
    my_serial.close()

