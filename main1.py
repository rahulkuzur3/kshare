import socket
import threading
import os
import qrcode
from io import BytesIO
import webbrowser
import time

from kivy.app import App
from kivy.lang import Builder
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.clock import Clock
from kivy.core.window import Window
from kivy.core.image import Image as CoreImage
from kivy.utils import platform
from kivy.uix.camera import Camera
from kivy.uix.popup import Popup
from kivy.uix.filechooser import FileChooserIconView
from kivy.storage.jsonstore import JsonStore
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.button import Button

# --- SCANNER CHECK ---
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
#        KIVY UI LAYOUT (KV LANGUAGE)
# ==========================================
KV_CODE = """
#:import utils kivy.utils

# --- CUSTOM WIDGETS ---
<CButton@Button>:
    background_normal: ''
    background_color: utils.get_color_from_hex('#3b82f6')
    color: 1, 1, 1, 1
    font_size: '16sp'
    bold: True
    size_hint_y: None
    height: '50dp'
    border_radius: [10]
    canvas.before:
        Color:
            rgba: self.background_color
        RoundedRectangle:
            size: self.size
            pos: self.pos
            radius: [10]

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
            radius: [15]
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
        font_size: '20sp'
        bold: True
        size_hint_y: 0.3
        color: 1, 1, 1, 1

<DarkInput@TextInput>:
    background_color: 0.2, 0.2, 0.2, 1
    foreground_color: 1, 1, 1, 1
    cursor_color: 1, 1, 1, 1
    multiline: False
    padding_y: [10, 10]
    size_hint_y: None
    height: '45dp'

# --- SCREENS ---
ScreenManager:
    MenuScreen:
    SendScreen:
    ScannerScreen:
    ReceiveScreen:
    SettingsScreen:

# ================= MENU SCREEN =================
<MenuScreen>:
    name: 'menu'
    FloatLayout:
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#0f172a')
            Rectangle:
                pos: self.pos
                size: self.size
        
        # Mini Settings Button (Top Right)
        Button:
            text: 'SETTINGS'
            font_size: '10sp'
            size_hint: None, None
            size: '70dp', '30dp'
            pos_hint: {'top': 0.98, 'right': 0.98}
            background_normal: ''
            background_color: utils.get_color_from_hex('#334155')
            on_release: app.root.current = 'settings'

        BoxLayout:
            orientation: 'vertical'
            padding: 30
            spacing: 20

            BoxLayout:
                orientation: 'vertical'
                size_hint_y: 0.35
                Image:
                    source: 'logo.png'
                    allow_stretch: True
                    keep_ratio: True
                Label:
                    text: 'KShare'
                    font_size: '32sp'
                    bold: True
                    color: utils.get_color_from_hex('#38bdf8')
                    size_hint_y: None
                    height: '40dp'

            GridLayout:
                cols: 2
                spacing: 20
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
                text: 'Fast & Secure P2P Transfer'
                color: 0.5, 0.5, 0.5, 1
                font_size: '12sp'
                size_hint_y: 0.1

# ================= SETTINGS SCREEN =================
<SettingsScreen>:
    name: 'settings'
    on_enter: app.update_settings_ui()
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 15
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#1e293b')
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
                spacing: 20
                padding: [0, 10, 0, 10]

                # --- DOWNLOAD LOCATION ---
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: '100dp'
                    spacing: 5
                    Label:
                        text: 'DOWNLOAD LOCATION'
                        text_size: self.size
                        halign: 'left'
                        bold: True
                        color: 0.8, 0.8, 0.8, 1
                        font_size: '14sp'
                    
                    Label:
                        id: path_label
                        text: 'C:/Users/...'
                        text_size: self.size
                        halign: 'left'
                        color: 0.6, 0.6, 0.6, 1
                        font_size: '12sp'
                    
                    Button:
                        text: 'Change Folder'
                        size_hint_y: None
                        height: '40dp'
                        background_normal: ''
                        background_color: utils.get_color_from_hex('#475569')
                        on_release: app.open_dir_chooser()

                # --- DEVELOPER ---
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: '100dp'
                    spacing: 5
                    Label:
                        text: 'DEVELOPER'
                        text_size: self.size
                        halign: 'left'
                        bold: True
                        color: 0.8, 0.8, 0.8, 1
                        font_size: '14sp'
                    
                    Label:
                        text: 'Rahul Kuzur'
                        font_size: '18sp'
                        color: 1, 1, 1, 1
                        size_hint_y: None
                        height: '30dp'

                    Button:
                        text: 'kuzur.uk'
                        color: utils.get_color_from_hex('#38bdf8')
                        background_color: 0,0,0,0
                        on_release: app.open_link("https://kuzur.uk")

                # --- ABOUT ---
                BoxLayout:
                    orientation: 'vertical'
                    size_hint_y: None
                    height: '120dp'
                    spacing: 5
                    Label:
                        text: 'ABOUT KSHARE'
                        text_size: self.size
                        halign: 'left'
                        bold: True
                        color: 0.8, 0.8, 0.8, 1
                        font_size: '14sp'
                    
                    Label:
                        text: 'Version: 1.4.0 Pro'
                        color: 0.5, 0.5, 0.5, 1
                        font_size: '11sp'

                    Button:
                        text: 'Visit Official Website'
                        color: utils.get_color_from_hex('#38bdf8')
                        background_color: 0,0,0,0
                        on_release: app.open_link("https://kuzur.uk/kshare")

        CButton:
            text: 'Back to Menu'
            background_color: utils.get_color_from_hex('#64748b')
            on_release: app.root.current = 'menu'

# ================= SEND SCREEN =================
<SendScreen>:
    name: 'send'
    on_enter: app.check_platform_ui()
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 15
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#1e293b')
            Rectangle:
                pos: self.pos
                size: self.size

        Label:
            text: 'Select File to Send'
            font_size: '18sp'
            bold: True
            size_hint_y: None
            height: '30dp'

        FileChooserIconView:
            id: filechooser
            path: app.get_home_dir()
            size_hint_y: 0.4

        Label:
            id: selected_file_lbl
            text: 'No file selected'
            color: 0.7, 0.7, 0.7, 1
            size_hint_y: None
            height: '30dp'
            shorten: True

        # Input Area
        BoxLayout:
            size_hint_y: None
            height: '45dp'
            spacing: 10
            DarkInput:
                id: target_ip
                hint_text: 'Enter Receiver IP'
                size_hint_x: 0.7
            Button:
                id: scan_btn
                text: 'SCAN QR'
                size_hint_x: 0.3
                background_color: utils.get_color_from_hex('#eab308')
                on_release: app.open_scanner()

        # --- SENDER TRANSFER CARD ---
        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.3
            padding: 15
            canvas.before:
                Color:
                    rgba: utils.get_color_from_hex('#0f172a')
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [15]
            
            Label:
                id: status_lbl
                text: 'Ready to Transfer'
                font_size: '14sp'
                color: 0.8, 0.8, 0.8, 1
                size_hint_y: 0.2
            
            Label:
                id: pct_lbl
                text: '0%'
                font_size: '40sp'
                bold: True
                color: utils.get_color_from_hex('#38bdf8')
                size_hint_y: 0.5
            
            ProgressBar:
                id: progress
                max: 100
                value: 0
                size_hint_y: None
                height: '10dp'

        BoxLayout:
            size_hint_y: None
            height: '50dp'
            spacing: 10
            CButton:
                text: 'Back'
                background_color: utils.get_color_from_hex('#64748b')
                on_release: app.root.current = 'menu'
            CButton:
                text: 'TRANSFER NOW'
                background_color: utils.get_color_from_hex('#3b82f6')
                on_release: app.start_transfer()

# ================= SCANNER SCREEN =================
<ScannerScreen>:
    name: 'scanner'
    BoxLayout:
        orientation: 'vertical'
        BoxLayout:
            id: camera_container
        CButton:
            text: 'Cancel'
            background_color: utils.get_color_from_hex('#ef4444')
            on_release: app.close_scanner()

# ================= RECEIVE SCREEN (UPDATED) =================
<ReceiveScreen>:
    name: 'receive'
    on_enter: app.prepare_receiver_ui()
    on_leave: app.stop_server()
    BoxLayout:
        orientation: 'vertical'
        padding: 20
        spacing: 10
        canvas.before:
            Color:
                rgba: utils.get_color_from_hex('#1e293b')
            Rectangle:
                pos: self.pos
                size: self.size

        Label:
            text: 'Scan to Connect'
            font_size: '20sp'
            bold: True
            color: utils.get_color_from_hex('#38bdf8')
            size_hint_y: None
            height: '35dp'

        # QR CODE
        Image:
            id: qr_image
            size_hint_y: 0.3
            allow_stretch: True
            keep_ratio: True

        Label:
            id: my_ip_lbl
            text: 'IP: ...'
            font_size: '16sp'
            bold: True
            size_hint_y: None
            height: '30dp'

        # --- RECEIVER TRANSFER CARD ---
        BoxLayout:
            orientation: 'vertical'
            size_hint_y: 0.3
            padding: 15
            canvas.before:
                Color:
                    rgba: utils.get_color_from_hex('#0f172a')
                RoundedRectangle:
                    pos: self.pos
                    size: self.size
                    radius: [15]

            Label:
                id: rx_status
                text: 'Waiting for sender...'
                font_size: '14sp'
                color: 0.8, 0.8, 0.8, 1
                size_hint_y: 0.2

            # BIG PERCENTAGE LABEL FOR RECEIVER
            Label:
                id: rx_pct_lbl
                text: '0%'
                font_size: '40sp'
                bold: True
                color: utils.get_color_from_hex('#38bdf8')
                size_hint_y: 0.5

            ProgressBar:
                id: rx_progress
                max: 100
                value: 0
                size_hint_y: None
                height: '10dp'

        CButton:
            text: 'Cancel'
            background_color: utils.get_color_from_hex('#ef4444')
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
    def get_save_path(self):
        return self.store.get('config')['save_path']

    def update_settings_ui(self):
        screen = self.root.get_screen('settings')
        screen.ids.path_label.text = self.get_save_path()

    def open_link(self, url):
        webbrowser.open(url)

    def open_dir_chooser(self):
        content = BoxLayout(orientation='vertical')
        filechooser = FileChooserIconView(path=self.get_save_path(), dirselect=True)
        btn_layout = BoxLayout(size_hint_y=None, height='50dp', spacing=10)
        select_btn = Button(text='Select Folder', background_color=(0,1,0,1))
        cancel_btn = Button(text='Cancel', background_color=(1,0,0,1))
        btn_layout.add_widget(cancel_btn)
        btn_layout.add_widget(select_btn)
        content.add_widget(filechooser)
        content.add_widget(btn_layout)
        popup = Popup(title='Choose Folder', content=content, size_hint=(0.9, 0.9))
        
        def select_path(instance):
            selected = filechooser.selection
            path = selected[0] if selected else filechooser.path
            self.store.put('config', save_path=path)
            self.update_settings_ui()
            popup.dismiss()

        select_btn.bind(on_release=select_path)
        cancel_btn.bind(on_release=popup.dismiss)
        popup.open()

    # --- UTILS ---
    def get_home_dir(self):
        return os.path.expanduser("~")

    def get_local_ip(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

    def check_platform_ui(self):
        screen = self.root.get_screen('send')
        if platform not in ('android', 'ios'):
            screen.ids.scan_btn.opacity = 0
            screen.ids.scan_btn.disabled = True
            screen.ids.scan_btn.size_hint_x = 0
            screen.ids.target_ip.size_hint_x = 1
        else:
            screen.ids.scan_btn.opacity = 1
            screen.ids.scan_btn.disabled = False
            screen.ids.scan_btn.size_hint_x = 0.3
            screen.ids.target_ip.size_hint_x = 0.7

    # --- SCANNER ---
    def open_scanner(self):
        if not SCANNER_AVAILABLE:
            self.root.get_screen('send').ids.status_lbl.text = "Scanner libs missing"
            return
        self.root.current = 'scanner'
        screen = self.root.get_screen('scanner')
        container = screen.ids.camera_container
        if not container.children:
            try:
                self.cam_widget = Camera(play=True, resolution=(640, 480))
                container.add_widget(self.cam_widget)
            except Exception:
                self.close_scanner()
                return
        self.scanner_event = Clock.schedule_interval(self.scan_qr_code, 0.2)

    def close_scanner(self):
        screen = self.root.get_screen('scanner')
        container = screen.ids.camera_container
        if container.children:
            cam = container.children[0]
            cam.play = False
            container.remove_widget(cam)
        if hasattr(self, 'scanner_event'):
            self.scanner_event.cancel()
        self.root.current = 'send'

    def scan_qr_code(self, dt):
        screen = self.root.get_screen('scanner')
        container = screen.ids.camera_container
        if not container.children: return
        camera = container.children[0]
        if not camera.texture: return
        texture = camera.texture
        nparr = np.frombuffer(texture.pixels, np.uint8)
        img = nparr.reshape(texture.size[1], texture.size[0], 4)
        gray = cv2.cvtColor(img, cv2.COLOR_RGBA2GRAY)
        decoded_objects = decode(gray)
        for obj in decoded_objects:
            detected_ip = obj.data.decode('utf-8')
            if "." in detected_ip:
                self.root.get_screen('send').ids.target_ip.text = detected_ip
                self.close_scanner()

    # --- GENERATE QR ---
    def generate_qr(self, data):
        qr = qrcode.QRCode(box_size=10, border=4)
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format='PNG')
        buffer.seek(0)
        return CoreImage(buffer, ext='png').texture

    # --- RECEIVE LOGIC (UPDATED WITH %) ---
    def prepare_receiver_ui(self):
        ip = self.get_local_ip()
        screen = self.root.get_screen('receive')
        screen.ids.my_ip_lbl.text = f"IP: {ip}"
        screen.ids.qr_image.texture = self.generate_qr(ip)
        self.start_server()

    def start_server(self):
        self.server_running = True
        self.server_thread = threading.Thread(target=self.server_loop)
        self.server_thread.daemon = True
        self.server_thread.start()

    def stop_server(self):
        self.server_running = False

    def server_loop(self):
        screen = self.root.get_screen('receive')
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_socket.bind(('0.0.0.0', 9000))
            server_socket.listen(1)
            server_socket.settimeout(2)
            while self.server_running:
                try:
                    client, addr = server_socket.accept()
                    Clock.schedule_once(lambda dt: setattr(screen.ids.rx_status, 'text', f"Receiving..."))
                    metadata = client.recv(1024).decode()
                    if "|" not in metadata: continue
                    filename, size_str = metadata.split('|')
                    filesize = int(size_str)
                    client.send("OK".encode())
                    
                    received = 0
                    save_dir = self.get_save_path()
                    save_path = os.path.join(save_dir, f"received_{filename}")
                    
                    with open(save_path, 'wb') as f:
                        while received < filesize:
                            data = client.recv(4096)
                            if not data: break
                            f.write(data)
                            received += len(data)
                            percent = (received / filesize) * 100
                            
                            # Update BOTH Progress Bar and Big Label
                            Clock.schedule_once(lambda dt, p=percent: self.update_rx_ui(screen, p))

                    client.close()
                    Clock.schedule_once(lambda dt, f=filename: setattr(screen.ids.rx_status, 'text', f"Saved: {f}"))
                    Clock.schedule_once(lambda dt: setattr(screen.ids.rx_pct_lbl, 'text', "100%"))
                except socket.timeout: continue
                except Exception as e:
                    Clock.schedule_once(lambda dt, err=str(e): setattr(screen.ids.rx_status, 'text', f"Error: {err}"))
                    break
        finally: server_socket.close()

    def update_rx_ui(self, screen, percent):
        """Updates Receiver Percentage Label and Bar"""
        screen.ids.rx_progress.value = percent
        screen.ids.rx_pct_lbl.text = f"{int(percent)}%"

    # --- SEND LOGIC ---
    def start_transfer(self):
        screen = self.root.get_screen('send')
        selection = screen.ids.filechooser.selection
        target_ip = screen.ids.target_ip.text.strip()
        if not selection:
            screen.ids.status_lbl.text = "Select a file first!"
            return
        if not target_ip:
            screen.ids.status_lbl.text = "Enter IP Address!"
            return
        threading.Thread(target=self.send_file_thread, args=(selection[0], target_ip)).start()

    def send_file_thread(self, filepath, ip):
        screen = self.root.get_screen('send')
        port = 9000
        try:
            Clock.schedule_once(lambda dt: setattr(screen.ids.status_lbl, 'text', "Connecting..."))
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((ip, port))
            filesize = os.path.getsize(filepath)
            filename = os.path.basename(filepath)
            s.send(f"{filename}|{filesize}".encode())
            ack = s.recv(1024).decode()
            if ack != "OK": raise Exception("Rejected")
            
            sent = 0
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(4096)
                    if not data: break
                    s.sendall(data)
                    sent += len(data)
                    percent = (sent / filesize) * 100
                    
                    Clock.schedule_once(lambda dt, p=percent: self.update_progress_ui(screen, p))

            s.close()
            Clock.schedule_once(lambda dt: setattr(screen.ids.status_lbl, 'text', "Transfer Complete!"))
            Clock.schedule_once(lambda dt: setattr(screen.ids.pct_lbl, 'text', "100%"))
        except Exception as e:
            Clock.schedule_once(lambda dt, err=str(e): setattr(screen.ids.status_lbl, 'text', f"Failed: {err}"))

    def update_progress_ui(self, screen, percent):
        screen.ids.progress.value = percent
        screen.ids.pct_lbl.text = f"{int(percent)}%"

if __name__ == '__main__':
    KShareApp().run()