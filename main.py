import flet as ft
import subprocess
import ctypes
import sys
import os
import platform
import threading
import time
import pygetwindow

COLOR_BACKGROUND = "#0A0A0A"
COLOR_TEXT_BLACK = "#0A0A0A"
COLOR_BACKGROUND_LIGHT = "#333333"
COLOR_GREEN = "#2CC295"
COLOR_RED = "#D32F2F"
COLOR_TEXT_PRIMARY = "#F5F5F5"
COLOR_TEXT_SECONDARY = "#B0B0B0"
COLOR_BORDER = "#333333"

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DPI_DIR = os.path.join(BASE_DIR, "goodbyedpi")
SERVICE_NAME = "GoodbyeDPI"

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_active_interface_index():
    """Finds the interface index of the active network adapter by looking for the default route."""
    try:
        command = "(Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Sort-Object -Property RouteMetric | Select-Object -First 1).InterfaceIndex"
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            check=True,
            capture_output=True,
            text=True,
            encoding="mbcs",
        )
        interface_index = result.stdout.strip()
        if interface_index and interface_index.isdigit():
            return int(interface_index)
        return None
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None

def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        base_path = sys._MEIPASS
    except Exception:
        if getattr(sys, 'frozen', False):
            base_path = os.path.dirname(sys.executable)
        else:
            base_path = os.path.abspath(".")

    return os.path.join(base_path, relative_path)

def main(page: ft.Page):
    page.title = "offveil - DNS & DPI Aracı"
    page.window_resizable = False
    page.window_maximizable = False
    
    icon_path = resource_path("offveil.ico")
    page.window_icon = icon_path

    page.theme_mode = ft.ThemeMode.DARK
    page.vertical_alignment = ft.MainAxisAlignment.START
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.bgcolor = COLOR_BACKGROUND
    page.padding = 0
    page.fonts = {
        "Inter": "https://rsms.me/inter/font-files/Inter-roman.var.woff2?v=4.0"
    }
    page.theme = ft.Theme(font_family="Inter")

    def force_window_size_and_center():
        try:
            time.sleep(0.5)
            win = pygetwindow.getWindowsWithTitle('offveil - DNS & DPI Aracı')[0]
            if win:
                win.resizeTo(430, 600)
                screen_width, screen_height = win.screen.width, win.screen.height
                win.moveTo((screen_width - 430) // 2, (screen_height - 600) // 2)
                win.activate()
        except Exception:
            pass

    threading.Thread(target=force_window_size_and_center, daemon=True).start()

    status_icon = ft.Icon(name="info_outline", size=16, color=COLOR_TEXT_SECONDARY)
    status_text = ft.Text("Başlamaya hazır.", size=14, color=COLOR_TEXT_SECONDARY, text_align=ft.TextAlign.CENTER, weight=ft.FontWeight.NORMAL)
    status_ring = ft.ProgressRing(width=16, height=16, stroke_width=2, visible=False)

    status_container = ft.Container(
        content=ft.Row(
            [
                ft.Stack([status_icon, status_ring]),
                status_text,
            ],
            alignment=ft.MainAxisAlignment.CENTER,
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=8,
        ),
        padding=ft.padding.symmetric(vertical=8),
        border=ft.border.all(1, COLOR_BORDER),
        border_radius=ft.border_radius.all(8),
        margin=ft.margin.only(bottom=20),
    )

    def show_status(text: str, success: bool = False, error: bool = False, info: bool = False):
        status_ring.visible = info
        status_icon.visible = not info

        icon_name = "check_circle" if success else ("error" if error else "info_outline")
        color = COLOR_GREEN if success else (COLOR_RED if error else COLOR_TEXT_SECONDARY)

        status_icon.name = icon_name
        status_icon.color = color
        
        status_text.value = text
        status_text.color = color if (success or error) else COLOR_TEXT_SECONDARY
        
        page.update()

    def install_dpi_internal(service_args, description="offveil DPI Service"):
        arch = "x86_64" if platform.machine().endswith("64") else "x86"
        exe_path = os.path.join(DPI_DIR, arch, "goodbyedpi.exe")
        if not os.path.exists(exe_path):
            show_status(f"Hata: {exe_path} bulunamadı!", error=True)
            return False

        try:
            show_status("Mevcut DPI hizmeti kaldırılıyor...", info=True)
            subprocess.run(f'sc stop "{SERVICE_NAME}"', shell=True, check=False, capture_output=True)
            subprocess.run(f'sc delete "{SERVICE_NAME}"', shell=True, check=False, capture_output=True)
            time.sleep(1)

            show_status("Yeni DPI hizmeti kuruluyor...", info=True)
            create_command = f'sc create "{SERVICE_NAME}" binPath= "\\"{exe_path}\\" {service_args}" start= auto'
            
            result = subprocess.run(create_command, shell=True, check=True, capture_output=True, text=True, encoding="mbcs")
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, create_command, output=result.stdout, stderr=result.stderr)

            subprocess.run(f'sc description "{SERVICE_NAME}" "{description}"', shell=True, check=True, capture_output=True)
            
            result = subprocess.run(f'sc start "{SERVICE_NAME}"', shell=True, check=True, capture_output=True, text=True, encoding="mbcs")
            if result.returncode != 0:
                raise subprocess.CalledProcessError(result.returncode, f'sc start "{SERVICE_NAME}"', output=result.stdout, stderr=result.stderr)

            show_status("DPI hizmeti başarıyla etkinleştirildi.", success=True)
            return True

        except subprocess.CalledProcessError as e:
            error_output = e.stderr.strip() if e.stderr else str(e)
            show_status(f"Hizmet hatası: {error_output}", error=True)
            return False

    def remove_dpi_internal():
        show_status("DPI hizmeti kaldırılıyor...", info=True)
        try:
            subprocess.run(f'sc stop "{SERVICE_NAME}"', shell=True, check=False, capture_output=True)
            subprocess.run(f'sc delete "{SERVICE_NAME}"', shell=True, check=False, capture_output=True)
            show_status("DPI hizmeti başarıyla kaldırıldı.", success=True)
            return True
        except Exception as e:
            show_status(f"Kaldırma hatası: {e}", error=True)
            return False
        
    def change_dns_internal():
        show_status("Aktif ağ adaptörü aranıyor...", info=True)
        interface_index = get_active_interface_index()
        if interface_index is None:
            show_status("Aktif ağ adaptörü bulunamadı!", error=True)
            return False
        
        show_status(f"Arayüz (Index: {interface_index}) için DNS ayarlanıyor...", info=True)
        
        cloudflare_dns_servers = "'1.1.1.1', '1.0.0.1', '2606:4700:4700::1111', '2606:4700:4700::1001'"
        ps_command = f"Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ServerAddresses ({cloudflare_dns_servers})"

        try:
            # Optimize edilmiş powershell çağrısı
            subprocess.run([
                "powershell", "-NoProfile", "-Command", f"{ps_command}; Clear-DnsClientCache"
            ], check=True, capture_output=True)
            show_status("Cloudflare DNS başarıyla ayarlandı.", success=True)
            return True
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.strip() if e.stderr else "Bilinmeyen PowerShell hatası."
            show_status(f"DNS ayarlanamadı: {error_output}", error=True)
            return False
        except FileNotFoundError:
            show_status("Hata: 'powershell' komutu bulunamadı.", error=True)
            return False

    def reset_dns_internal():
        show_status("Aktif ağ adaptörü aranıyor...", info=True)
        interface_index = get_active_interface_index()
        if interface_index is None:
            show_status("Aktif ağ adaptörü bulunamadı!", error=True)
            return False

        show_status(f"Arayüz (Index: {interface_index}) için DNS sıfırlanıyor...", info=True)

        try:
            ps_command = f"Set-DnsClientServerAddress -InterfaceIndex {interface_index} -ResetServerAddresses"
            subprocess.run([
                "powershell", "-NoProfile", "-Command", f"{ps_command}; Clear-DnsClientCache"
            ], check=True, capture_output=True)
            show_status("DNS başarıyla sıfırlandı (DHCP).", success=True)
            return True
        except subprocess.CalledProcessError as e:
            error_output = e.stderr.strip() if e.stderr else "Bilinmeyen PowerShell hatası."
            show_status(f"DNS sıfırlanamadı: {error_output}", error=True)
            return False
        except FileNotFoundError:
            show_status("Hata: 'powershell' komutu bulunamadı.", error=True)
            return False

    DEFAULT_DPI_ARGS = "-5 --set-ttl 5 --dns-addr 1.1.1.1 --dns-port 53 --dnsv6-addr 2606:4700:4700::1111 --dnsv6-port 53"
    ALT_DESCRIPTION = "TR Alternatif Versiyonu Superonline"

    def activate_dns_dpi(e):
        dns_ok = change_dns_internal()
        if not dns_ok:
            show_status("DNS ayarlanamadığı için DPI etkinleştirilmedi.", error=True)
            return
        dpi_ok = install_dpi_internal(service_args=DEFAULT_DPI_ARGS)
        if dns_ok and dpi_ok:
            show_status("DNS & DPI başarıyla etkinleştirildi.", success=True)
        else:
            show_status("Bir veya daha fazla işlem başarısız oldu.", error=True)
    
    def activate_dns_only(e):
        change_dns_internal()
    
    def activate_dpi_only(e):
        install_dpi_internal(service_args=DEFAULT_DPI_ARGS)

    def activate_dpi_alt_1(e):
        install_dpi_internal(service_args="--set-ttl 3", description=ALT_DESCRIPTION)

    def activate_dpi_alt_2(e):
        install_dpi_internal(service_args="-5", description=ALT_DESCRIPTION)

    def activate_dpi_alt_3(e):
        install_dpi_internal(service_args="--set-ttl 3 --dns-addr 1.1.1.1 --dns-port 53 --dnsv6-addr 2606:4700:4700::1111 --dnsv6-port 53", description=ALT_DESCRIPTION)

    def reset_all(e):
        dns_reset_ok = reset_dns_internal()
        dpi_removed_ok = remove_dpi_internal()
        if dns_reset_ok and dpi_removed_ok:
            show_status("Tüm ayarlar başarıyla sıfırlandı.", success=True)
        else:
            show_status("Sıfırlama sırasında bir hata oluştu.", error=True)

    # UI Components
    def create_main_button(text, icon, on_click, color, expand=False, bgcolor=COLOR_GREEN, textcolor=COLOR_TEXT_BLACK):
        return ft.FilledButton(
            content=ft.Row(
                [
                    ft.Icon(icon, color=color, size=20),
                    ft.Text(value=text, color=textcolor, weight=ft.FontWeight.W_600, size=15),
                ],
                alignment=ft.MainAxisAlignment.CENTER,
                spacing=15,
                vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            on_click=on_click,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                padding=ft.padding.all(18),
                bgcolor=bgcolor,
            ),
            expand=expand,
        )
    
    def create_alt_button(text, on_click):
        return ft.OutlinedButton(
            text=text,
            on_click=on_click,
            style=ft.ButtonStyle(
                shape=ft.RoundedRectangleBorder(radius=8),
                padding=ft.padding.symmetric(vertical=15, horizontal=10),
                side=ft.BorderSide(1, COLOR_BORDER),
                color=COLOR_TEXT_SECONDARY,
            ),
            expand=True,
        )

    # Header
    header = ft.Container(
        content=ft.Column(
            [
                ft.Image(
                    src=resource_path("offveil.png"),
                    width=150,
                    height=75,
                    fit=ft.ImageFit.CONTAIN,
                ),
                ft.TextButton(
                    content=ft.Text(
                        "erayselim.com tarafından geliştirildi",
                        size=13,
                        color=COLOR_TEXT_PRIMARY,
                        weight=ft.FontWeight.W_400
                    ),
                    url="https://erayselim.com",
                    style=ft.ButtonStyle(
                        padding=ft.padding.all(0),
                    ),
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=2,
        ),
        alignment=ft.alignment.center,
        padding=ft.padding.only(top=20, bottom=0),
    )

    # Buttons
    action_section = ft.Column(
        spacing=15,
        controls=[
            create_main_button(
                "Önerilen DNS & DPI Ayarlarını Uygula",
                "security_rounded",
                activate_dns_dpi,
                COLOR_TEXT_BLACK,
                expand=True,
            ),
            ft.Row(
                spacing=10,
                controls=[
                    create_main_button(
                        "DNS Değiştir", 
                        "dns_rounded", 
                        activate_dns_only,
                        COLOR_TEXT_BLACK,
                        expand=True,
                    ),
                    create_main_button(
                        "DPI Etkinleştir", 
                        "shield_rounded",
                        activate_dpi_only,
                        COLOR_TEXT_BLACK,
                        expand=True,
                    ),
                ]
            ),
            ft.Container(
                content=ft.Column(
                    controls=[
                        ft.Row(
                            spacing=10,
                            controls=[
                                create_alt_button("Alternatif 1", activate_dpi_alt_1),
                                create_alt_button("Alternatif 2", activate_dpi_alt_2),
                                create_alt_button("Alternatif 3", activate_dpi_alt_3),
                            ],
                        ),
                    ],
                    spacing=8,
                ),
                margin=ft.margin.symmetric(vertical=10),
            ),
            create_main_button(
                "Tüm Ayarları Sıfırla", 
                "restore_rounded", 
                reset_all,
                COLOR_TEXT_PRIMARY,
                expand=True,
                bgcolor=COLOR_RED,
                textcolor=COLOR_TEXT_PRIMARY,
            ),
        ],
        horizontal_alignment=ft.CrossAxisAlignment.STRETCH,
    )

    # Info Card
    info_card = ft.Container(
        content=ft.Column(
            [
                ft.Text(
                    "Yalnızca yasal kullanım amaçlıdır.",
                    size=13,
                    color=COLOR_TEXT_SECONDARY,
                    text_align=ft.TextAlign.CENTER,
                ),
                ft.Row(
                    [
                        ft.Text("Krediler:", color=COLOR_TEXT_SECONDARY),
                        ft.TextButton(
                            "ValdikSS",
                            url="https://github.com/ValdikSS/GoodbyeDPI",
                            style=ft.ButtonStyle(color=COLOR_TEXT_PRIMARY, padding=2),
                        ),
                        ft.Text("|", color=COLOR_TEXT_SECONDARY),
                        ft.TextButton(
                            "cagritaskn",
                            url="https://github.com/cagritaskn/GoodbyeDPI-Turkey",
                            style=ft.ButtonStyle(color=COLOR_TEXT_PRIMARY, padding=2),
                        ),
                    ],
                    alignment=ft.MainAxisAlignment.CENTER,
                    spacing=5,
                ),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            spacing=8,
        ),
        padding=ft.padding.symmetric(horizontal=20, vertical=15),
        margin=ft.margin.only(top=20),
    )

    # Main Layout
    page.add(
        ft.Container(
            content=ft.Column(
                [
                    header,
                    ft.Container(
                        padding=ft.padding.symmetric(horizontal=30, vertical=20),
                        content=ft.Column(
                            [
                                status_container,
                                action_section,
                                info_card,
                            ],
                            spacing=0
                        ),
                    ),
                ],
                scroll=ft.ScrollMode.AUTO,
                spacing=0,
                horizontal_alignment=ft.CrossAxisAlignment.CENTER,
            ),
            expand=True,
            alignment=ft.alignment.top_center,
        )
    )

if __name__ == "__main__":
    if is_admin():
        ft.app(target=main)
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1) 