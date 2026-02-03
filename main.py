import socket
import threading
import os
import qrcode
import sys
import webbrowser
from io import BytesIO

# Kivy Core Imports
from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.core.image import Image as CoreImage
from kivy.utils import platform
from kivy.resources import resource_add_path
from kivy.storage.jsonstore import JsonStore

from kivy.uix.camera import Camera
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserIconView
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button

# --- EXE FIX (Must be at the very top) ---
if hasattr(sys, '_MEIPASS'):
    resource_add_path(sys._MEIPASS)

# --- SCANNER DEPENDENCIES CHECK ---
try:
    from pyzbar.pyzbar import decode
    import cv2
    import numpy as np
    SCANNER_AVAILABLE = True
except Exception:
    SCANNER_AVAILABLE = False

if platform not in ('android', 'ios'):
    Window.size = (400, 750)

# ==========================================
#        KIVY UI LAYOUT (FIXED SYNTAX)
# ==========================================
KV_CODE = """
#:import utils kivy.utils

<CButton@Button>:
    background_normal: ''
    background_color: utils.get_color_from_hex('#3b82f6')
    color: 1, 1, 1, 1
    font_size: '16sp'
    bold: True
    size_hint_y: None
    height: '50dp'
    border_radius: [12]
    canvas.before:
        Color:
            rgba: self.background_color
        RoundedRectangle:
            size: self.size
            pos: self.pos
            radius: [12]

<MenuTile@ButtonBehavior+BoxLayout>:
    orientation: 'vertical'
    padding: 20
    spacing: 10
    canvas.before:
        Color:
            rgba: root.background_color
        RoundedRectangle:
            pos: self.pos
            size: self.size
            radius: [20]
    source: ''
    text: ''
    background_color: [0,0,0,0]
    Image:
        source: root.source
        allow_stretch: True
        keep_ratio: True
        size_hint_y: 0.7
    Label:
        text: root.text
        font_size: '18sp'
        bold: True
        size_hint_y: 0.3
        color: 1, 1, 1, 1

<DarkInput@TextInput>:
    background_color: 0.2, 0.2, 0.2, 1
    foreground_color: 1, 1, 1, 1
    cursor_color: 1, 1, 1, 1
    multiline: False
    padding_y: [12, 12]
    size_hint_y: None
    height: '48dp'

ScreenManager:
    MenuScreen:
    SendScreen:
    ScannerScreen:
    ReceiveScreen:
    SettingsScreen:

# ----------------- MENU -----------------
<MenuScreen>:
    name: 'menu'
    FloatLayout:
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#0f172a')
            Rectangle:
                pos: self.pos
                size: self.size
        
        Button:
            text: 'SETTINGS'
            font_size: '11sp'
            size_hint: None, None
            size: '90dp', '35dp'
            pos_hint: {'top': 0.98, 'right': 0.98}
            background_normal: ''
            background_color: utils.get_color_from_hex('#334155')
            on_release: app.root.current = 'settings'

        BoxLayout:
            orientation: 'vertical'
            padding: 40
            spacing: 30
            BoxLayout:
                orientation: 'vertical'
                size_hint_y: 0.3
                Image:
                    source: 'logo.png'
                    allow_stretch: True
                    keep_ratio: True
                Label:
                    text: 'KShare'
                    font_size: '36sp'
                    bold: True
                    color: utils.get_color_from_hex('#38bdf8')
            GridLayout:
                cols: 2
                spacing: 25
                size_hint_y: 0.4
                MenuTile:
                    text: 'SEND'
                    source: 'send.png'
                    background_color: utils.get_color_from_hex('#10b981')
                    on_release: app.root.current = 'send'
                MenuTile:
                    text: 'RECEIVE'
                    source: 'receive.png'
                    background_color: utils.get_color_from_hex('#6366f1')
                    on_release: app.root.current = 'receive'
            Label:
                text: 'Direct P2P File Transfer'
                color: 0.5, 0.5, 0.5, 1
                font_size: '13sp'
                size_hint_y: 0.1

# ----------------- RECEIVE SCREEN -----------------
<ReceiveScreen>:
    name: 'receive'
    on_enter: app.prepare_receiver_ui()
    on_leave: app.stop_server()
    BoxLayout:
        orientation: 'vertical'
        padding: 25
        spacing: 15
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#0f172a')
            Rectangle:
                pos: self.pos
                size: self.size
        
        Label:
            text: 'RECEIVE FILE'
            font_size: '22sp'
            bold: True
            size_hint_y: None
            height: '40dp'
            color: utils.get_color_from_hex('#38bdf8')

        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.5
            padding: 10
            canvas.before:
                Color:
                    rgba: 1, 1, 1, 0.05
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [20]
            
            Image:
                id: qr_image
                allow_stretch: True
                keep_ratio: True
            
            Label:
                id: my_ip_lbl
                text: 'IP: 0.0.0.0'
                font_size: '16sp'
                bold: True
                color: utils.get_color_from_hex('#94a3b8')
                size_hint_y: None
                height: '30dp'

        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.3
            padding: 20
            spacing: 10
            canvas.before:
                Color:
                    rgba: utils.get_color_from_hex('#1e293b')
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [20]
            
            Label:
                id: rx_status
                text: 'Waiting for connection...'
                font_size: '14sp'
                color: 0.7, 0.7, 0.7, 1
            
            Label:
                id: rx_pct_lbl
                text: '0%'
                font_size: '42sp'
                bold: True
                color: utils.get_color_from_hex('#38bdf8')
            
            ProgressBar:
                id: rx_progress
                max: 100
                value: 0
                size_hint_y: None
                height: '8dp'

        CButton:
            text: 'BACK TO MENU'
            background_color: utils.get_color_from_hex('#ef4444')
            on_release: app.root.current = 'menu'

# ----------------- SEND SCREEN -----------------
<SendScreen>:
    name: 'send'
    on_enter: app.check_platform_ui()
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 15
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#0f172a')
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: 'SELECT FILE'
            font_size: '20sp'
            bold: True
            size_hint_y: None
            height: '40dp'
            color: utils.get_color_from_hex('#10b981')
        FileChooserIconView:
            id: filechooser
            path: app.get_home_dir()
            size_hint_y: 0.4
        Label:
            id: selected_file_lbl
            text: 'No file selected'
            color: 0.5, 0.5, 0.5, 1
            size_hint_y: None
            height: '30dp'
            shorten: True
        BoxLayout:
            size_hint_y: None
            height: '45dp'
            spacing: 10
            DarkInput:
                id: target_ip
                hint_text: 'Receiver IP Address'
                size_hint_x: 0.7
            Button:
                text: 'SCAN'
                id: scan_btn
                size_hint_x: 0.3
                background_color: utils.get_color_from_hex('#eab308')
                on_release: app.open_scanner()
        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.25
            padding: 20
            canvas.before:
                Color:
                    rgba: utils.get_color_from_hex('#1e293b')
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [20]
            Label:
                id: status_lbl
                text: 'Ready'
                font_size: '14sp'
            Label:
                id: pct_lbl
                text: '0%'
                font_size: '36sp'
                bold: True
                color: utils.get_color_from_hex('#10b981')
            ProgressBar:
                id: progress
                max: 100
                value: 0
        BoxLayout:
            size_hint_y: None
            height: '50dp'
            spacing: 10
            CButton:
                text: 'BACK'
                background_color: utils.get_color_from_hex('#64748b')
                on_release: app.root.current = 'menu'
            CButton:
                text: 'START TRANSFER'
                on_release: app.start_transfer()

# ----------------- SCANNER (FIXED SYNTAX) -----------------
<ScannerScreen>:
    name: 'scanner'
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            id: camera_container
        CButton:
            text: 'CANCEL SCAN'
            background_color: utils.get_color_from_hex('#ef4444')
            on_release: app.close_scanner()

# ----------------- SETTINGS (FIXED SYNTAX) -----------------
<SettingsScreen>:
    name: 'settings'
    on_enter: app.update_settings_ui()
    BoxLayout:
        orientation: 'vertical'
        padding: 25
        spacing: 15
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#0f172a')
            Rectangle:
                pos: self.pos
                size: self.size
        Label:
            text: 'SETTINGS'
            font_size: '22sp'
            bold: True
            size_hint_y: None
            height: '50dp'
            color: utils.get_color_from_hex('#38bdf8')
        ScrollView:
            BoxLayout:
                orientation: 'vertical'
                size_hint_y: None
                height: self.minimum_height
                spacing: 25
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: '100dp'
                    Label:
                        text: 'DOWNLOAD DIRECTORY'
                        bold: True
                        font_size: '14sp'
                    Label:
                        id: path_label
                        text: ''
                        font_size: '11sp'
                        color: 0.6, 0.6, 0.6, 1
                    CButton:
                        text: 'Change Folder'
                        height: '40dp'
                        on_release: app.open_dir_chooser()
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: '100dp'
                    Label:
                        text: 'DEVELOPER INFO'
                        bold: True
                    Label:
                        text: 'Rahul Kuzur'
                        font_size: '18sp'
                    Button:
                        text: 'kuzur.uk'
                        color: utils.get_color_from_hex('#38bdf8')
                        background_color: 0,0,0,0
                        on_release: app.open_link("https://kuzur.uk")
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: '100dp'
                    Label:
                        text: 'App INFO'
                        bold: True
                    Label:
                        text: 'Version 1.0.0'
                        font_size: '13sp'
                    Label:
                        text: 'Official Website'
                        font_size: '18sp'
                    Button:
                        text: 'kshare.kuzur.uk'
                        color: utils.get_color_from_hex('#38bdf8')
                        background_color: 0,0,0,0
                        on_release: app.open_link("https://kshare.kuzur.uk")              
        CButton:
            text: 'BACK'
            background_color: utils.get_color_from_hex('#64748b')
            on_release: app.root.current = 'menu'
"""

class MenuScreen(Screen): pass
class SendScreen(Screen): pass
class ScannerScreen(Screen): pass
class ReceiveScreen(Screen): pass
class SettingsScreen(Screen): pass

class KShareApp(App):
    def build(self):
        self.title = 'KShare'
        self.store = JsonStore('kshare_settings.json')
        if not self.store.exists('config'):
            self.store.put('config', save_path=os.path.expanduser("~"))
        return Builder.load_string(KV_CODE)

    # --- SETTINGS LOGIC ---
    def get_save_path(self): return self.store.get('config')['save_path']
    def update_settings_ui(self): self.root.get_screen('settings').ids.path_label.text = self.get_save_path()
    def open_link(self, url): webbrowser.open(url)
    def open_dir_chooser(self):
        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserIconView(path=self.get_save_path(), dirselect=True)
        btns = BoxLayout(size_hint_y=None, height='50dp')
        s_btn = Button(text='Select', background_color=(0,1,0,1))
        c_btn = Button(text='Cancel', background_color=(1,0,0,1))
        btns.add_widget(c_btn); btns.add_widget(s_btn)
        content.add_widget(filechooser); content.add_widget(btns)
        p = Popup(title='Select Save Folder', content=content, size_hint=(0.9, 0.9))
        def select_path(i):
            selected = filechooser.selection[0] if filechooser.selection else filechooser.path
            self.store.put('config', save_path=selected)
            self.update_settings_ui(); p.dismiss()
        s_btn.bind(on_release=select_path); c_btn.bind(on_release=p.dismiss); p.open()

    # --- UTILS ---
    def get_home_dir(self): return os.path.expanduser("~")
    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try: s.connect(('8.8.8.8', 80)); ip = s.getsockname()[0]
        except: ip = '127.0.0.1'
        finally: s.close()
        return ip

    def check_platform_ui(self):
        s = self.root.get_screen('send')
        if platform not in ('android', 'ios'):
            s.ids.scan_btn.opacity = 0; s.ids.scan_btn.disabled = True
            s.ids.scan_btn.size_hint_x = 0; s.ids.target_ip.size_hint_x = 1
        else:
            s.ids.scan_btn.opacity = 1; s.ids.scan_btn.disabled = False
            s.ids.scan_btn.size_hint_x = 0.3; s.ids.target_ip.size_hint_x = 0.7

    # --- SCANNER ---
    def open_scanner(self):
        if not SCANNER_AVAILABLE: return
        self.root.current = 'scanner'
        c = self.root.get_screen('scanner').ids.camera_container
        if not c.children:
            try: cam = Camera(play=True, resolution=(640, 480)); c.add_widget(cam)
            except: self.close_scanner(); return
        self.scanner_event = Clock.schedule_interval(self.scan_qr_code, 0.2)

    def close_scanner(self):
        c = self.root.get_screen('scanner').ids.camera_container
        if c.children: cam = c.children[0]; cam.play = False; c.remove_widget(cam)
        if hasattr(self, 'scanner_event'): self.scanner_event.cancel()
        self.root.current = 'send'

    def scan_qr_code(self, dt):
        c = self.root.get_screen('scanner').ids.camera_container
        if not c.children or not c.children[0].texture: return
        t = c.children[0].texture; n = np.frombuffer(t.pixels, np.uint8)
        img = n.reshape(t.size[1], t.size[0], 4); gray = cv2.cvtColor(img, cv2.COLOR_RGBA2GRAY)
        for o in decode(gray):
            res = o.data.decode('utf-8')
            if "." in res: self.root.get_screen('send').ids.target_ip.text = res; self.close_scanner()

    # --- RECEIVE LOGIC ---
    def prepare_receiver_ui(self):
        ip = self.get_local_ip(); s = self.root.get_screen('receive')
        s.ids.my_ip_lbl.text = f"IP Address: {ip}"
        qr = qrcode.QRCode(box_size=10, border=2); qr.add_data(ip); qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = BytesIO(); img.save(buf, format='PNG'); buf.seek(0)
        s.ids.qr_image.texture = CoreImage(buf, ext='png').texture
        s.ids.rx_pct_lbl.text = "0%"; s.ids.rx_progress.value = 0; s.ids.rx_status.text = "Waiting for connection..."
        self.start_server()

    def start_server(self):
        self.server_running = True
        self.server_thread = threading.Thread(target=self.server_loop)
        self.server_thread.daemon = True; self.server_thread.start()

    def stop_server(self): self.server_running = False

    def server_loop(self):
        s = self.root.get_screen('receive')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(('0.0.0.0', 9000)); sock.listen(1); sock.settimeout(2)
            while self.server_running:
                try:
                    c, addr = sock.accept()
                    Clock.schedule_once(lambda dt: setattr(s.ids.rx_status, 'text', f"Connected to {addr[0]}"))
                    meta = c.recv(1024).decode()
                    if "|" not in meta: continue
                    name, size = meta.split('|'); size = int(size); c.send("OK".encode())
                    received = 0; save_path = os.path.join(self.get_save_path(), f"received_{name}")
                    with open(save_path, 'wb') as f:
                        while received < size:
                            data = c.recv(4096)
                            if not data: break
                            f.write(data); received += len(data); p = (received/size)*100
                            Clock.schedule_once(lambda dt, p=p: self.update_rx_ui(s, p))
                    c.close()
                    Clock.schedule_once(lambda dt: setattr(s.ids.rx_status, 'text', f"Received: {name}"))
                    Clock.schedule_once(lambda dt: setattr(s.ids.rx_pct_lbl, 'text', "100%"))
                except socket.timeout: continue
                except: break
        finally: sock.close()

    def update_rx_ui(self, s, p):
        s.ids.rx_progress.value = p; s.ids.rx_pct_lbl.text = f"{int(p)}%"

    # --- SEND LOGIC ---
    def start_transfer(self):
        s = self.root.get_screen('send'); sel = s.ids.filechooser.selection; ip = s.ids.target_ip.text.strip()
        if not sel or not ip: return
        threading.Thread(target=self.send_file_thread, args=(sel[0], ip)).start()

    def send_file_thread(self, path, ip):
        s = self.root.get_screen('send')
        try:
            Clock.schedule_once(lambda dt: setattr(s.ids.status_lbl, 'text', "Connecting..."))
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM); sock.connect((ip, 9000))
            size = os.path.getsize(path); name = os.path.basename(path)
            sock.send(f"{name}|{size}".encode())
            if sock.recv(1024).decode() != "OK": return
            sent = 0
            with open(path, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data: break
                    sock.sendall(data); sent += len(data); p = (sent/size)*100
                    Clock.schedule_once(lambda dt, p=p: self.update_tx_ui(s, p))
            sock.close()
            Clock.schedule_once(lambda dt: setattr(s.ids.status_lbl, 'text', "Transfer Complete!"))
        except: Clock.schedule_once(lambda dt: setattr(s.ids.status_lbl, 'text', "Connection Failed!"))

    def update_tx_ui(self, s, p):
        s.ids.progress.value = p; s.ids.pct_lbl.text = f"{int(p)}%"

if __name__ == '__main__':
    KShareApp().run()