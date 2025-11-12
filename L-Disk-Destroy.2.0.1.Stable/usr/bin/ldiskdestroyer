#!/usr/bin/env python3

import sys
import os
import subprocess
import threading
import fcntl
import termios 
import struct 
import re
import time
import signal
import tempfile 

from PySide6.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QComboBox, QMessageBox, QFrame, QLineEdit, QSizePolicy, QProgressBar 
)
from PySide6.QtGui import QPixmap, QFont, QIcon
from PySide6.QtCore import Qt, QThread, Signal, QTimer, QSize

# DDWorker Sınıfı
class DDWorker(QThread): 
    # pyqtSignal yerine PySide6'da QtCore.Signal kullanılır
    progress_update = Signal(str, int) 
    process_finished = Signal(bool, str)
    pid_found = Signal(int)

    def __init__(self, device, parent=None):
        super().__init__(parent)
        self.device = device
        self.pkexec_process = None
        self.worker_pid = None 
        self.stop_flag = False
        self.pid_file = "/tmp/disk_destroyer_worker_pid.tmp" 
        self.temp_script_path = None 

    def run(self):
        try:
            self.progress_update.emit(self.tr("attempt_unmount"), 0)
            
            partitions = self.get_device_partitions(self.device)
            unmount_commands = ""
            if partitions:
                for part in partitions:
                    unmount_commands += f"umount -f {part} || true; " 
                self.progress_update.emit(self.tr("unmounting_all_partitions"), 0)
            else:
                self.progress_update.emit(self.tr("no_partitions_to_unmount"), 0)

            # TÜM İŞLEMLERİ TEK BİR pkexec ÇAĞRISINDA BİRLEŞTİRİLİYOR (GEÇİCİ BETİK İLE)
            # shred'i arka planda başlat ve PID'yi dosyaya yaz.
            # Ardından bekleyip çıktıları oku.
            # -z parametresi KALDIRILDI, böylece sadece 1 geçiş rastgele veri yazılır.
            command_script_content = f"""#!/bin/bash
{unmount_commands}
nohup shred -v -n 1 {self.device} & echo $! > {self.pid_file}
wait $(cat {self.pid_file})
"""
            # Geçici bir betik dosyası oluştur
            with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as temp_script:
                temp_script.write(command_script_content)
                self.temp_script_path = temp_script.name
            
            os.chmod(self.temp_script_path, 0o755) 

            command = ["pkexec", self.temp_script_path]

            self.pkexec_process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, 
                text=True,
                bufsize=1
            )
            self.progress_update.emit(self.tr("pkexec_started_waiting_for_auth"), 0)

            start_time = time.time()
            while self.worker_pid is None and (time.time() - start_time) < 10 and self.pkexec_process.poll() is None:
                if os.path.exists(self.pid_file) and os.path.getsize(self.pid_file) > 0:
                    try:
                        with open(self.pid_file, 'r') as f:
                            pid_str = f.read().strip()
                            if pid_str.isdigit():
                                self.worker_pid = int(pid_str)
                                self.pid_found.emit(self.worker_pid)
                                self.progress_update.emit(self.tr("worker_pid_found").format(self.worker_pid), 0)
                                break
                    except Exception as e:
                        self.progress_update.emit(self.tr("error_reading_worker_pid_file").format(e), 0)
                time.sleep(0.1)
            
            if self.worker_pid is None and self.pkexec_process.poll() is None:
                self.progress_update.emit(self.tr("warn_worker_pid_unknown"), 0)
            elif self.worker_pid is None and self.pkexec_process.poll() is not None:
                self.progress_update.emit(self.tr("pkexec_exited_auth"), 0)
                self.process_finished.emit(False, self.tr("operation_cancelled_auth"))
                return 

            total_size = self.get_device_size(self.device)
            if total_size == 0:
                self.progress_update.emit(self.tr("warn_no_total_size"), 0)
            
            for line in iter(self.pkexec_process.stdout.readline, ''):
                if self.stop_flag:
                    self.progress_update.emit(self.tr("stop_flag_detected"), 0)
                    break

                stripped_line = line.strip()
                match_shred_progress = re.search(r'(\d+\.?\d*[KMGTPEZY]?i?B)/(\d+\.?\d*[KMGTPEZY]?i?B)', stripped_line)
                if match_shred_progress:
                    current_human = match_shred_progress.group(1)
                    total_human = match_shred_progress.group(2)
                    
                    try:
                        current_bytes = self._parse_human_readable_size(current_human)
                        total_bytes_shred = self._parse_human_readable_size(total_human)
                        
                        percentage = 0
                        if total_bytes_shred > 0:
                            percentage = int((current_bytes / total_bytes_shred) * 100)
                            if percentage > 100: percentage = 100 
                            progress_text = self.tr("shred_in_progress_pct").format(percentage, current_human, total_human)
                        else:
                            progress_text = self.tr("shred_in_progress_no_pct").format(current_human, total_human)
                            
                        self.progress_update.emit(progress_text, percentage)
                    except ValueError: 
                        self.progress_update.emit(stripped_line, 0)
                else:
                    if stripped_line and not stripped_line.startswith("shred:"): 
                        self.progress_update.emit(stripped_line, 0)

            self.pkexec_process.stdout.close()
            return_code = self.pkexec_process.wait()

            if self.stop_flag:
                self.process_finished.emit(False, self.tr("explicitly_stopped"))
            elif return_code == 0:
                self.process_finished.emit(True, self.tr("wipe_completed_success"))
            else:
                error_message = self.tr("wipe_failed_exit_code").format(return_code)
                if return_code == 1: 
                    error_message += self.tr("wipe_failed_reasons")
                self.process_finished.emit(False, error_message)

        except FileNotFoundError:
            self.process_finished.emit(False, self.tr("shred_command_not_found"))
        except Exception as e:
            self.process_finished.emit(False, self.tr("unexpected_error").format(e))
        finally:
            if self.temp_script_path and os.path.exists(self.temp_script_path):
                try:
                    os.remove(self.temp_script_path)
                    self.progress_update.emit(self.tr("temp_script_removed").format(self.temp_script_path), 0)
                except Exception as e:
                    self.progress_update.emit(self.tr("warn_temp_script_not_removed").format(self.temp_script_path, e), 0)

            pass 

    def _is_process_running(self, pid):
        if not pid:
            return False
        try:
            result = subprocess.run(["pkexec", "ps", "-p", str(pid), "-o", "pid,comm"], check=True, capture_output=True, text=True, timeout=5)
            lines = result.stdout.strip().splitlines()
            if len(lines) > 1 and str(pid) in lines[1]:
                return True
            return False
        except subprocess.CalledProcessError:
            return False
        except subprocess.TimeoutExpired:
            self.progress_update.emit(self.tr("warn_pkexec_ps_timeout").format(pid), 0)
            return True 
        except Exception as e:
            self.progress_update.emit(self.tr("error_pkexec_ps_check").format(pid, e), 0)
            return True

    def _parse_human_readable_size(self, size_str):
        size_str = size_str.strip().upper()
        if not size_str:
            return 0
        
        units = {
            'B': 1, 'KIB': 1024, 'MIB': 1024**2, 'GIB': 1024**3, 'TIB': 1024**4,
            'PIB': 1024**5, 'EIB': 1024**6, 'ZIB': 1024**7, 'YIB': 1024**8,
            'KB': 1000, 'MB': 1000**2, 'GB': 1000**3, 'TB': 1000**4,
            'PB': 1000**5, 'EB': 1000**6, 'ZB': 1000**7, 'YB': 1000**8
        }
        
        match = re.match(r'([\d.]+)\s*([KMGTPEZY]?I?B)?', size_str, re.IGNORECASE)
        if not match:
            raise ValueError(self.tr("error_parse_size_string").format(size_str))
        
        value = float(match.group(1))
        unit = match.group(2).upper() if match.group(2) else 'B'
        
        if unit not in units:
            raise ValueError(self.tr("error_unknown_unit").format(unit))
            
        return int(value * units[unit])

    def stop(self):
        self.stop_flag = True

    def get_device_size(self, device_path):
        try:
            output = subprocess.check_output(["lsblk", "-b", "-n", "-o", "SIZE", device_path], text=True, timeout=5).strip()
            if output.isdigit():
                return int(output)
            else:
                with open(device_path, 'rb') as f:
                    BLKGETSIZE64 = 0x80081272 
                    size_bytes = struct.unpack('Q', fcntl.ioctl(f, BLKGETSIZE64))[0]
                    return size_bytes
        except Exception as e:
            print(self.tr("debug_error_getting_device_size").format(device_path, e))
            return 0
            
    def get_device_partitions(self, device_path):
        partitions = []
        try:
            output = subprocess.check_output(["lsblk", "-P", "-o", "KNAME,PKNAME"], text=True, timeout=5).strip()
            device_base_name = os.path.basename(device_path)
            for line in output.splitlines():
                if not line.strip():
                    continue
                
                kname_match = re.search(r'KNAME="([^"]+)"', line)
                pkname_match = re.search(r'PKNAME="([^"]*)"', line)

                kname = kname_match.group(1) if kname_match else None
                pkname = pkname_match.group(1) if pkname_match else None

                if kname and pkname == device_base_name:
                    partitions.append(f"/dev/{kname}")
        except Exception as e:
            print(self.tr("debug_error_getting_partitions").format(device_path, e))
        return partitions

    def tr(self, key):
        if self.parent() and hasattr(self.parent(), 'get_translation'):
            return self.parent().get_translation(key)
        return key 


# LinuxDiskDestroyer Sınıfı
class LinuxDiskDestroyer(QWidget):
    def __init__(self):
        super().__init__()
        self.dd_worker = None
        self.dd_pid = None 
        self.pkexec_process_pid = None 
        
        # <<< ÇEVİRİLER VE SÜRÜM BİLGİLERİ GÜNCELLENDİ >>>
        self.translations = {
            'en': {
                'target_device': "Target Device:",
                'general_warning': (
                    "Warning! Before disposing of your various storage devices (including flash drives), "
                    "Linux Disk Destroyer performs a secure deletion, preventing the recipient from "
                    "accessing your private data with data recovery programs. This process is "
                    "irreversible. This process will not damage your storage devices. However, depending "
                    "on the size and type of your drive, this process can take a considerable amount of time."
                ),
                'ready_to_destroy': "Ready to destroy.",
                'destroy_button': "Destroy!",
                'stop_button': "Stop",
                'about_button': "About",
                'language_button': "Language",
                'confirm_destruction_title': "Confirm Destruction",
                'confirm_destruction_msg_1': (
                    "<b>WARNING!</b> Make sure you have selected the correct disk: <b>{}</b>!<br><br>"
                    "This operation is irreversible. It will attempt to fill the entire disk with random data. This process will "
                    "permanently erase ALL data."
                ),
                'confirm_destruction_msg_2': (
                    "Are you absolutely sure you want to securely wipe: <b>{}</b>?\n\n"
                    "THIS ACTION IS IRREVERSIBLE AND WILL PERMANENTLY DELETE ALL DATA!"
                ),
                'starting_destruction': "Starting destruction...",
                'operation_cancelled_auth': "Operation cancelled or failed at authentication step.",
                'pkexec_started_waiting_for_auth': "pkexec started. Waiting for authentication...",
                'success_title': "Success",
                'operation_outcome_title': "Operation Outcome",
                'about_title': "About Linux Disk Destroyer",
                'about_text': (
                    "<b>Linux Disk Destroyer</b><br>"
                    "Version: 2.0.0<br>"
                    "License: GPLv3<br>"
                    "Developer: A. Serhat KILIÇOĞLU (shampuan)<br>"
                    "Github: <a href='https://www.github.com/shampuan'>www.github.com/shampuan</a><br><br>"
                    
                    "A secure disk wiping tool for Debian-based Linux systems.<br>"
                    "Uses 'shred' for secure data destruction.<br><br>"
                    "Developed with Python3 and PySide6.<br>"
                    "Warning: Use the program carefully. This operation is irreversible!<br><br>"
                    
                    "This program comes with absolutely no warranty.<br><br>"
                    "Copyright © 2025 - A. Serhat KILIÇOĞLU"
                ),
                'app_closing_title': "Application Closing",
                'app_closing_msg': (
                    "A disk destruction process is running. Are you sure you want to exit? "
                    "Exiting will terminate the process and may leave the disk in an inconsistent state."
                ),
                'no_devices_found': "No block devices found.",
                'lsblk_not_found': "lsblk command not found. Please ensure it's installed.",
                'lsblk_timed_out': "lsblk command timed out. It might be stuck or the system is slow.",
                'lsblk_failed': "lsblk command failed with error: {}",
                'failed_list_devices': "Failed to list devices: {}",
                'select_target_device': "Please select a target device.",
                'parse_device_error': "Could not parse selected device path.",
                'shred_command_not_found': "Error: 'pkexec' or 'shred' command not found. Make sure they are installed.",
                'unexpected_error': "An unexpected error occurred: {}",
                'stop_flag_detected': "Stop flag detected. Attempting to terminate worker process...",
                
                'sending_term_signal_worker_with_password_attempt': "Sending termination signal to worker process (password will be asked)...",
                'sent_term_signal_worker_with_password': "Sent SIGTERM to worker process (PID: {}) via pkexec. Authentication required to stop.",
                'warn_term_timeout_worker_with_password': "Warning: Sending SIGTERM to worker (PID: {}) timed out. Trying SIGKILL (authentication required)...",
                'sent_kill_signal_worker_with_password': "Sent SIGKILL to worker process (PID: {}) via pkexec. Authentication required to stop.",
                'crit_kill_failed_worker_with_password': "Critical: Failed to send SIGKILL to worker (PID: {}): {}. Process might still be running. Manual termination might be required.",
                'error_send_kill_worker_with_password': "Error sending kill signal via pkexec to worker (PID: {}): {}. Manual termination might be required.",
                'worker_pid_unknown_fall_back_with_password': "Worker process PID not found. Falling back to pkexec process termination (authentication required).",
                'terminating_pkexec_with_password_attempt': "Attempting to terminate pkexec process (authentication required)...",
                'pkexec_still_running_sending_kill_with_password': "pkexec process still running after TERM, sending KILL (authentication required).",
                'warn_pkexec_not_terminated_with_password': "Warning: Failed to terminate pkexec process (authentication was asked): {}. Process might still be running. Manual termination might be required.",
                'pkexec_terminated_with_password': "Pkexec process terminated (authentication was asked).",
                'error_pkexec_kill_failed': "pkexec kill command failed: {}. Authentication might have been cancelled or failed.",
                'error_pkexec_kill_timeout': "pkexec kill command timed out. Authentication might be pending or slow.",
                'unexpected_error_during_pkexec_kill': "An unexpected error occurred during pkexec kill: {}. Manual termination might be required.",
                'why_password_to_stop': "To securely stop the disk destruction, your system requires authentication because the shred process runs with administrative privileges. This ensures the integrity and security of your system.", 
                
                'warn_process_not_found': "Warning: Process (PID: {}) not found when attempting to send kill signal.",
                'attempt_unmount': "Attempting to unmount device and its partitions...",
                'unmounting_all_partitions': "Unmounting all device partitions...",
                'unmounted_all_success': "All device partitions successfully unmounted.",
                'warn_unmount_timeout_all': "Warning: Unmount of some partitions timed out.",
                'warn_could_not_unmount_all': "Warning: Could not unmount some partitions: {}",
                'warn_error_unmount_all': "Warning: Error during unmount of some partitions: {}",
                'no_partitions_to_unmount': "No partitions found to unmount on this device.",
                'warn_some_unmount_fail_overall': "Warning: Some partitions could not be unmounted. This might cause shred to fail.",
                'warn_worker_pid_unknown': "Warning: Could not determine worker process PID. Stop might be delayed or less reliable.",
                'pkexec_exited_auth': "pkexec process exited before worker could be found. Likely password cancellation or failure.",
                'warn_no_total_size': "Warning: Could not determine total device size. Progress percentage will not be shown.",
                'shred_in_progress_pct': "Operation in progress: {:.2f}% ({}/{})",
                'shred_in_progress_no_pct': "Operation in progress: {} copied, total {}",
                'explicitly_stopped': "Operation explicitly stopped by user.",
                'wipe_completed_success': "Disk wiping completed successfully.",
                'wipe_failed_exit_code': "Disk wiping failed with exit code: {}",
                'wipe_failed_reasons': "\nPossible reasons: Insufficient permissions, device is mounted, or I/O error.\nEnsure the device is not in use (e.g., no files open, not mounted) and you have necessary permissions.",
                'no_pkexec_found': "No pkexec process found to terminate or it already finished.",
                
                'worker_pid_found': "Worker PID found: {}",
                'error_reading_worker_pid_file': "Error reading worker PID file: {}",
                'temp_script_removed': "Temporary script file removed: {}",
                'warn_temp_script_not_removed': "Warning: Could not remove temporary script file {}: {}",
                'warn_pkexec_ps_timeout': "Warning: pkexec ps check for PID {} timed out.",
                'error_pkexec_ps_check': "Error checking process {} status via pkexec ps: {}",
                'error_parse_size_string': "Could not parse size string: {}",
                'error_unknown_unit': "Unknown unit: {}",
                'debug_error_getting_device_size': "DEBUG: Error getting device size for {} (lsblk or ioctl): {}",
                'debug_error_getting_partitions': "DEBUG: Error getting partitions for {}: {}",
            },
            'tr': {
                'target_device': "Hedef Cihaz:",
                'general_warning': (
                    "UYARI! Çeşitli depolama cihazlarınızı (flash sürücüler dahil) elden çıkarmadan önce, "
                    "Linux Disk Destroyer güvenli bir silme işlemi gerçekleştirerek, alıcının veri kurtarma "
                    "programlarıyla özel verilerinize erişmesini engeller. Bu işlem geri alınamaz. Bu işlem "
                    "depolama cihazlarınıza zarar vermez. Ancak, sürücünüzün boyutuna ve türüne bağlı olarak, "
                    "bu işlem önemli ölçüde zaman alabilir."
                ),
                'ready_to_destroy': "Yok etmeye hazır.",
                'destroy_button': "Yok Et!",
                'stop_button': "Durdur",
                'about_button': "Hakkında",
                'language_button': "Dil",
                'confirm_destruction_title': "Yok Etmeyi Onayla",
                'confirm_destruction_msg_1': (
                    "<b>UYARI!</b> Doğru diski seçtiğinizden emin olun: <b>{}</b>!<br><br>"
                    "Bu işlem geri alınamaz. Diskin tamamını rastgele veriyle doldurmaya çalışacaktır. Bu işlem "
                    "TÜM verileri kalıcı olarak silecektir."
                ),
                'confirm_destruction_msg_2': (
                    "<b>{}</b> diskini güvenli bir şekilde silmek istediğinizden kesinlikle emin misiniz?\n\n"
                    "BU İŞLEM GERİ ALINAMAZ VE TÜM VERİLERİ KALICI OLARAK SİLECEKTİR!"
                ),
                'starting_destruction': "Yok etme başlatılıyor...",
                'operation_cancelled_auth': "Kimlik doğrulama adımında işlem iptal edildi veya başarısız oldu.",
                'pkexec_started_waiting_for_auth': "pkexec başlatıldı. Kimlik doğrulama bekleniyor...",
                'success_title': "Başarılı",
                'operation_outcome_title': "İşlem Sonucu",
                'about_title': "Linux Disk Destroyer Hakkında",
                'about_text': (
                    "<b>Linux Disk Destroyer</b><br>"
                    "Sürüm: 2.0.0<br>"
                    "Lisans: GPLv3<br>"
                    "Developer: A. Serhat KILIÇOĞLU (shampuan)<br>"
                    "Github: <a href='https://www.github.com/shampuan'>www.github.com/shampuan</a><br><br>"
                    
                    "Debian tabanlı Linux sistemleri için güvenli bir disk silme aracı.<br>"
                    "Güvenli veri yok etme için 'shred' kullanır.<br><br>"
                    "Python3 ve PySide6 ile geliştirilmiştir.<br>" 
                    "Uyarı: Programı dikkatli kullanın. Bu işlem geri alınamaz!<br><br>"
                    
                    "Bu program, hiçbir garanti getirmiyor.<br><br>"
                    "Telif hakkı © 2025 - A. Serhat KILIÇOĞLU"
                ),
                'app_closing_title': "Uygulama Kapanıyor",
                'app_closing_msg': (
                    "Bir disk yok etme işlemi devam ediyor. Çıkmak istediğinizden emin misiniz? "
                    "Çıkış yapmak işlemi sonlandıracak ve diski tutarsız bir durumda bırakabilir."
                ),
                'no_devices_found': "Blok cihaz bulunamadı.",
                'lsblk_not_found': "lsblk komutu bulunamadı. Lütfen kurulu olduğundan emin olun.",
                'lsblk_timed_out': "lsblk komutu zaman aşımına uğradı. Takılmış olabilir veya sistem yavaş olabilir.",
                'lsblk_failed': "lsblk komutu şu hatayla başarısız oldu: {}",
                'failed_list_devices': "Cihazlar listelenemedi: {}",
                'select_target_device': "Lütfen bir hedef cihaz seçin.",
                'parse_device_error': "Seçilen cihaz yolu ayrıştırılamadı.",
                'shred_command_not_found': "Hata: 'pkexec' veya 'shred' komutu bulunamadı. Kurulu olduğundan emin olun.",
                'unexpected_error': "Beklenmedik bir hata oluştu: {}",
                'stop_flag_detected': "Durdurma bayrağı algılandı. Çalışan süreç sonlandırmaya çalışılıyor...",
                
                'sending_term_signal_worker_with_password_attempt': "Çalışan sürece sonlandırma sinyali gönderiliyor (parola istenecek)...",
                'sent_term_signal_worker_with_password': "Çalışan sürece (PID: {}) pkexec aracılığıyla SIGTERM gönderildi. Durdurmak için kimlik doğrulama gerekli.",
                'warn_term_timeout_worker_with_password': "Uyarı: Çalışan sürece (PID: {}) SIGTERM gönderme zaman aşımına uğradı. SIGKILL deniyor (kimlik doğrulama gerekli)...",
                'sent_kill_signal_worker_with_password': "Çalışan sürece (PID: {}) pkexec aracılığıyla SIGKILL gönderildi. Durdurmak için kimlik doğrulama gerekli.",
                'crit_kill_failed_worker_with_password': "Kritik: Çalışan sürece (PID: {}) SIGKILL gönderilemedi: {}. Süreç hala çalışıyor olabilir. Manuel sonlandırma gerekebilir.",
                'error_send_kill_worker_with_password': "Çalışan sürece (PID: {}) pkexec aracılığıyla öldürme sinyali gönderme hatası: {}. Manuel sonlandırma gerekebilir.",
                'worker_pid_unknown_fall_back_with_password': "Çalışan süreç PID'si bulunamadı. pkexec süreci sonlandırmaya geri dönülüyor (kimlik doğrulama gerekli).",
                'terminating_pkexec_with_password_attempt': "pkexec sürecini sonlandırmaya çalışılıyor (kimlik doğrulama gerekli)...",
                'pkexec_still_running_sending_kill_with_password': "pkexec süreci TERM sonrası hala çalışıyor, KILL gönderiliyor (kimlik doğrulama gerekli).",
                'warn_pkexec_not_terminated_with_password': "Uyarı: pkexec süreci sonlandırılamadı (kimlik doğrulama istendi): {}. Süreç hala çalışıyor olabilir. Manuel sonlandırma gerekebilir.",
                'pkexec_terminated_with_password': "Pkexec süreci sonlandırıldı (kimlik doğrulama istendi).",
                'error_pkexec_kill_failed': "pkexec kill komutu başarısız oldu: {}. Kimlik doğrulama iptal edilmiş veya başarısız olmuş olabilir.",
                'error_pkexec_kill_timeout': "pkexec kill komutu zaman aşımına uğradı. Kimlik doğrulama beklemede veya yavaş olabilir.",
                'unexpected_error_during_pkexec_kill': "pkexec kill sırasında beklenmedik bir hata oluştu: {}. Manuel sonlandırma gerekebilir.",
                'why_password_to_stop': "Disk yok etme işlemini güvenli bir şekilde durdurmak için sisteminiz kimlik doğrulama gerektirir, çünkü 'shred' işlemi yönetici ayrıcalıklarıyla çalışır. Bu, sisteminizin bütünlüğünü ve sistem güvenliğini sağlar.",
                
                'warn_process_not_found': "Uyarı: Sinyal gönderilmeye çalışılırken süreç (PID: {}) bulunamadı.",
                'attempt_unmount': "Cihaz ve bölümleri ayrılmaya çalışılıyor...",
                'unmounting_all_partitions': "Tüm cihaz bölümleri ayrılıyor...",
                'unmounted_all_success': "Tüm cihaz bölümleri başarıyla ayrıldı.",
                'warn_unmount_timeout_all': "Uyarı: Bazı bölümlerin ayrılması zaman aşımına uğradı.",
                'warn_could_not_unmount_all': "Uyarı: Bazı bölümler ayrılamadı: {}",
                'warn_error_unmount_all': "Uyarı: Bazı bölümlerin ayrılması sırasında hata: {}",
                'no_partitions_to_unmount': "Bu cihazda ayrılacak bölüm bulunamadı.",
                'warn_some_unmount_fail_overall': "Uyarı: Bazı bölümler ayrılamadı. Bu, shred'in başarısız olmasına neden olabilir.",
                'warn_worker_pid_unknown': "Uyarı: Doğrudan sonlandırma için çalışan süreç PID'si belirlenemedi. Durdurma gecikebilir veya daha az güvenilir olabilir.",
                'pkexec_exited_auth': "Pkexec süreci çalışan süreç bulunamadan çıktı. Muhtemelen parola iptali veya hatası.",
                'warn_no_total_size': "Uyarı: Toplam cihaz boyutu belirlenemedi. İlerleme yüzdesi gösterilmeyecektir.",
                'shred_in_progress_pct': "İşlem devam ediyor: {:.2f}% ({}/{})", 
                'shred_in_progress_no_pct': "İşlem devam ediyor: {} kopyalandı, toplam {}", 
                'explicitly_stopped': "İşlem kullanıcı tarafından açıkça durduruldu.",
                'wipe_completed_success': "Disk silme işlemi başarıyla tamamlandı.",
                'wipe_failed_exit_code': "Disk silme işlemi şu çıkış koduyla başarısız oldu: {}",
                'wipe_failed_reasons': "\nOlası nedenler: Yetersiz izinler, cihaz bağlı veya G/Ç hatası.\nCihazın kullanımda olmadığından (örn. açık dosya yok, bağlı değil) ve gerekli izinlere sahip olduğunuzdan emin olun.",
                'no_pkexec_found': "Sonlandırılacak bir pkexec süreci bulunamadı veya zaten bitmişti.",

                'worker_pid_found': "Çalışan PID bulundu: {}",
                'error_reading_worker_pid_file': "Çalışan PID dosyası okunurken hata: {}",
                'temp_script_removed': "Geçici betik dosyası kaldırıldı: {}",
                'warn_temp_script_not_removed': "Uyarı: Geçici betik dosyası {} kaldırılamadı: {}",
                'warn_pkexec_ps_timeout': "Uyarı: PID {} için pkexec ps kontrolü zaman aşımına uğradı.",
                'error_pkexec_ps_check': "Süreç {} durumu pkexec ps aracılığıyla kontrol edilirken hata: {}",
                'error_parse_size_string': "Boyut dizesi ayrıştırılamadı: {}",
                'error_unknown_unit': "Bilinmeyen birim: {}",
                'debug_error_getting_device_size': "HATA AYIKLAMA: {} için cihaz boyutu alınırken hata (lsblk veya ioctl): {}",
                'debug_error_getting_partitions': "HATA AYIKLAMA: {} için bölümler alınırken hata: {}",
            }
        }
        self.current_language = 'en'
        
        self.init_ui()
        self.load_icons()
        self.populate_devices()
        self.update_ui_texts()

    def get_translation(self, key):
        return self.translations[self.current_language].get(key, key)

    def get_icon_path(self, icon_name):
        # 1. Programın çalıştığı betiğin klasörüne göre ikonları ara (Geliştirme/Kaynak Kodu Çalıştırma için)
        script_dir = os.path.dirname(os.path.abspath(__file__))
        local_path = os.path.join(script_dir, "icons", icon_name)
        if os.path.exists(local_path):
            return local_path

        # 2. Belirtilen sistemsel kurulum dizininde ara (Kurulum sonrası için)
        system_path = os.path.join("/usr/share/linux-disk-destroyer/icons", icon_name)
        if os.path.exists(system_path):
            return system_path
        
        return "" # Hiçbir yerde bulunamazsa boş döndür

    def load_icons(self):
        # Uygulama ikonu ayarlanır, bu ikon QMessageBox.about'ta da görünür.
        self.setWindowIcon(QIcon(self.get_icon_path("windowicon.png")))

        button_icon_target_size = 32

        self.destroy_button.setIconSize(QSize(button_icon_target_size, button_icon_target_size))
        self.destroy_button.setIcon(QIcon(self.get_icon_path("destroybutton.png")))
        
        self.stop_button.setIconSize(QSize(button_icon_target_size, button_icon_target_size))
        self.stop_button.setIcon(QIcon(self.get_icon_path("stop.png")))
        
        # Yeni ikonlar burada ekleniyor
        self.language_button.setIconSize(QSize(button_icon_target_size, button_icon_target_size))
        self.language_button.setIcon(QIcon(self.get_icon_path("lang.png")))
        
        self.about_button.setIconSize(QSize(button_icon_target_size, button_icon_target_size))
        self.about_button.setIcon(QIcon(self.get_icon_path("about.png"))) # Yeni ikon
        
        emblem_path = self.get_icon_path("emblem.png")
        if os.path.exists(emblem_path):
            self.emblem_label.setPixmap(QPixmap(emblem_path))
            self.emblem_label.setFixedSize(64, 64)
            self.emblem_label.setScaledContents(True)

    def init_ui(self):
        self.setWindowTitle("Linux Disk Destroyer")
        self.setGeometry(100, 100, 600, 400)
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        title_section_frame = QFrame()
        title_section_frame.setFrameShape(QFrame.StyledPanel)
        title_section_frame.setFrameShadow(QFrame.Sunken)
        title_section_frame.setContentsMargins(10, 10, 10, 10)
        title_section_layout = QHBoxLayout(title_section_frame)
        title_section_layout.setContentsMargins(0, 0, 0, 0)
        
        title_section_layout.addStretch(1)

        self.emblem_label = QLabel()
        self.emblem_label.setAlignment(Qt.AlignCenter)
        title_section_layout.addWidget(self.emblem_label)

        title_label = QLabel("Linux Disk Destroyer")
        title_font = QFont("Arial", 24, QFont.Bold)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        title_section_layout.addWidget(title_label)
        
        title_section_layout.addStretch(1)

        main_layout.addWidget(title_section_frame)

        target_device_frame = QFrame()
        target_device_frame.setFrameShape(QFrame.StyledPanel)
        target_device_frame.setFrameShadow(QFrame.Sunken)
        target_device_frame.setContentsMargins(10, 10, 10, 10)
        
        target_device_frame_layout = QVBoxLayout(target_device_frame)
        target_device_frame_layout.setContentsMargins(10, 10, 10, 10) 

        device_selection_layout = QHBoxLayout()
        device_selection_layout.setContentsMargins(0, 0, 0, 0)

        self.target_label = QLabel(self.get_translation('target_device'))
        self.target_label.setFont(QFont("Arial", 10, QFont.Bold))
        self.target_label.setAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        device_selection_layout.addWidget(self.target_label)

        self.device_combo = QComboBox()
        self.device_combo.setMinimumHeight(30)
        self.device_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        device_selection_layout.addWidget(self.device_combo)

        target_device_frame_layout.addLayout(device_selection_layout)

        self.general_warning_label = QLabel(self.get_translation('general_warning'))
        self.general_warning_label.setWordWrap(True)
        self.general_warning_label.setFont(QFont("Arial", 9))
        target_device_frame_layout.addWidget(self.general_warning_label)
        
        main_layout.addWidget(target_device_frame)

        # Progress elements
        self.progress_label = QLabel(self.get_translation('ready_to_destroy'))
        self.progress_label.setFont(QFont("Monospace", 9))
        self.progress_label.setWordWrap(True)
        main_layout.addWidget(self.progress_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%p%") 
        main_layout.addWidget(self.progress_bar)

        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        button_layout.addStretch(1)

        self.destroy_button = QPushButton(self.get_translation('destroy_button'))
        self.destroy_button.setFixedSize(120, 40)
        self.destroy_button.setFont(QFont("Arial", 10, QFont.Bold))
        self.destroy_button.clicked.connect(self.prompt_destruction_confirmation) 
        button_layout.addWidget(self.destroy_button)

        self.stop_button = QPushButton(self.get_translation('stop_button'))
        self.stop_button.setFixedSize(120, 40)
        self.stop_button.setFont(QFont("Arial", 10, QFont.Bold))
        self.stop_button.setEnabled(False) 
        self.stop_button.clicked.connect(self.stop_destruction_process) 
        button_layout.addWidget(self.stop_button)

        self.language_button = QPushButton(self.get_translation('language_button'))
        self.language_button.setFixedSize(120, 40)
        self.language_button.setFont(QFont("Arial", 10, QFont.Bold))
        self.language_button.clicked.connect(self.toggle_language)
        button_layout.addWidget(self.language_button)

        self.about_button = QPushButton(self.get_translation('about_button'))
        self.about_button.setFixedSize(120, 40)
        self.about_button.setFont(QFont("Arial", 10, QFont.Bold))
        self.about_button.clicked.connect(self.show_about_dialog)
        button_layout.addWidget(self.about_button)

        main_layout.addLayout(button_layout)
        self.setLayout(main_layout)

    def update_ui_texts(self):
        self.target_label.setText(self.get_translation('target_device'))
        self.general_warning_label.setText(self.get_translation('general_warning'))
        self.progress_label.setText(self.get_translation('ready_to_destroy'))
        self.destroy_button.setText(self.get_translation('destroy_button'))
        self.stop_button.setText(self.get_translation('stop_button'))
        self.language_button.setText(self.get_translation('language_button'))
        self.about_button.setText(self.get_translation('about_button'))
        self.progress_bar.setValue(0) 

    def toggle_language(self):
        if self.current_language == 'en':
            self.current_language = 'tr'
        else:
            self.current_language = 'en'
        self.update_ui_texts()
        self.populate_devices()

    def populate_devices(self):
        self.device_combo.clear()
        try:
            output = subprocess.check_output(["lsblk", "-ndo", "KNAME,TYPE,SIZE,MODEL"], text=True, timeout=10).strip()
            
            devices = []
            for line in output.splitlines():
                if not line.strip():
                    continue
                
                parts = re.split(r'\s+', line.strip(), 3)
                
                if len(parts) >= 2:
                    kname = parts[0]
                    dev_type = parts[1]
                    size = parts[2] if len(parts) > 2 else "N/A"
                    model = parts[3] if len(parts) > 3 else "N/A"
                    
                    if dev_type == "disk":
                        device_path = f"/dev/{kname}"
                        if os.path.exists(device_path):
                            devices.append(f"{device_path} ({size} - {model})")
            
            if not devices:
                self.device_combo.addItem(self.get_translation('no_devices_found'))
                self.destroy_button.setEnabled(False)
            else:
                self.device_combo.addItems(devices)
                self.destroy_button.setEnabled(True)

        except FileNotFoundError:
            QMessageBox.critical(self, "Hata", self.get_translation('lsblk_not_found'))
            self.destroy_button.setEnabled(False)
        except subprocess.TimeoutExpired:
            QMessageBox.critical(self, "Hata", self.get_translation('lsblk_timed_out'))
            self.destroy_button.setEnabled(False)
        except subprocess.CalledProcessError as e:
            QMessageBox.critical(self, "Hata", self.get_translation('lsblk_failed').format(e.stderr.strip()))
            self.destroy_button.setEnabled(False)
        except Exception as e:
            QMessageBox.critical(self, "Hata", self.get_translation('failed_list_devices').format(e))
            self.destroy_button.setEnabled(False)

    def prompt_destruction_confirmation(self):
        selected_device_text = self.device_combo.currentText()
        if not selected_device_text or self.get_translation('no_devices_found') in selected_device_text:
            QMessageBox.warning(self, self.get_translation('select_target_device'), self.get_translation('select_target_device'))
            return

        match = re.match(r'(/dev/\w+)', selected_device_text)
        if not match:
            QMessageBox.critical(self, "Hata", self.get_translation('parse_device_error'))
            return
        
        selected_device_path = match.group(1)

        reply1 = QMessageBox.warning(
            self,
            self.get_translation('confirm_destruction_title'),
            self.get_translation('confirm_destruction_msg_1').format(selected_device_text),
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )

        if reply1 == QMessageBox.Yes:
            reply2 = QMessageBox.warning(
                self,
                self.get_translation('confirm_destruction_title'),
                self.get_translation('confirm_destruction_msg_2').format(selected_device_text),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply2 == QMessageBox.Yes:
                self.start_destruction_process(selected_device_path)
            else:
                self.progress_label.setText(self.get_translation('ready_to_destroy'))
                self.progress_bar.setValue(0)
        else:
            self.progress_label.setText(self.get_translation('ready_to_destroy'))
            self.progress_bar.setValue(0)

    def start_destruction_process(self, device_path):
        if self.dd_worker and self.dd_worker.isRunning():
            QMessageBox.warning(self, "İşlem Devam Ediyor", "Zaten bir disk yok etme işlemi çalışıyor.")
            return

        self.progress_label.setText(self.get_translation('starting_destruction'))
        self.progress_bar.setValue(0)
        self.destroy_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.device_combo.setEnabled(False)
        self.about_button.setEnabled(False)
        self.language_button.setEnabled(False)

        self.dd_worker = DDWorker(device_path, parent=self)
        self.dd_worker.progress_update.connect(self.update_progress)
        self.dd_worker.process_finished.connect(self.destruction_finished)
        self.dd_worker.pid_found.connect(self.set_dd_pid)
        self.dd_worker.start()
        if self.dd_worker.pkexec_process:
            self.pkexec_process_pid = self.dd_worker.pkexec_process.pid
            print(f"DEBUG: pkexec process PID set to: {self.pkexec_process_pid}")


    def stop_destruction_process(self):
        if self.dd_worker and self.dd_worker.isRunning():
            QMessageBox.information(self, self.get_translation('stop_button'), 
                                     self.get_translation('why_password_to_stop'))
            
            self.dd_worker.stop() 

            stop_script_content = """#!/bin/bash
            PID_FILE="/tmp/disk_destroyer_worker_pid.tmp"
            
            SHRED_PID=0
            if [ -f "$PID_FILE" ] && [ -s "$PID_FILE" ]; then
                SHRED_PID=$(cat "$PID_FILE")
            fi

            echo "DEBUG: Stop script initiated. SHRED_PID=$SHRED_PID"
            
            if [ "$SHRED_PID" -gt 0 ]; then
                if ps -p $SHRED_PID > /dev/null; then 
                    echo "DEBUG: Sending SIGTERM to shred (PID: $SHRED_PID)..."
                    kill -TERM $SHRED_PID
                    sleep 1.5
                    if ps -p $SHRED_PID > /dev/null; then
                        echo "DEBUG: shred (PID: $SHRED_PID) still running after TERM, sending SIGKILL..."
                        kill -KILL $SHRED_PID
                        sleep 1.5
                    fi
                else
                    echo "DEBUG: Shred process (PID: $SHRED_PID) not found or already exited."
                fi
            else
                echo "DEBUG: Shred PID not found in $PID_FILE."
            fi

            if [ -f "$PID_FILE" ]; then
                echo "DEBUG: Removing PID file $PID_FILE..."
                rm -f "$PID_FILE"
            fi
            """
            
            with tempfile.NamedTemporaryFile(mode='w', delete=False, encoding='utf-8') as stop_script:
                stop_script.write(stop_script_content)
                temp_stop_script_path = stop_script.name
            os.chmod(temp_stop_script_path, 0o755)

            try:
                self.progress_label.setText(self.get_translation('sending_term_signal_worker_with_password_attempt'))
                self.progress_bar.setValue(self.progress_bar.value()) 
                stop_result = subprocess.run(["pkexec", temp_stop_script_path], check=False, capture_output=True, text=True, timeout=10)
                
                print(f"DEBUG: Stop script stdout:\n{stop_result.stdout}")
                print(f"DEBUG: Stop script stderr:\n{stop_result.stderr}")

                if stop_result.returncode == 0:
                    self.progress_label.setText(self.get_translation('explicitly_stopped'))
                else:
                    self.progress_label.setText(self.get_translation('crit_kill_failed_worker_with_password').format(self.dd_pid, stop_result.stderr))
                
            except FileNotFoundError:
                self.progress_label.setText(self.get_translation('shred_command_not_found')) 
            except subprocess.TimeoutExpired:
                self.progress_label.setText(self.get_translation('error_pkexec_kill_timeout'))
            except Exception as e:
                self.progress_label.setText(self.get_translation('unexpected_error_during_pkexec_kill').format(e))
            finally:
                if os.path.exists(temp_stop_script_path):
                    os.remove(temp_stop_script_path)
                    print(f"DEBUG: Temporary stop script removed: {temp_stop_script_path}")

            self.dd_worker.wait(5000) 

        else:
            self.progress_label.setText(self.get_translation('ready_to_destroy'))
            self.progress_bar.setValue(0)

    def set_dd_pid(self, pid):
        self.dd_pid = pid
        print(f"DEBUG: shred process PID set to: {self.dd_pid}")

    def update_progress(self, message, percentage):
        self.progress_label.setText(message)
        self.progress_bar.setValue(percentage)

    def destruction_finished(self, success, message):
        self.progress_label.setText(message)
        self.destroy_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.device_combo.setEnabled(True)
        self.about_button.setEnabled(True)
        self.language_button.setEnabled(True)
        self.dd_pid = None 
        self.pkexec_process_pid = None 

        if success:
            self.progress_bar.setValue(100) 
            QMessageBox.information(self, self.get_translation('success_title'), message)
        else:
            self.progress_bar.setValue(self.progress_bar.value()) 
            QMessageBox.warning(self, self.get_translation('operation_outcome_title'), message)
        
        self.populate_devices() 

    def show_about_dialog(self):
        # QMessageBox.about statik yöntemi, uygulama ikonunu ve HTML formatlı metni destekler.
        # Bu, PySide6'nın varsayılan, temiz ve sistem temasına uygun stilini korur.
        QMessageBox.about(
            self, 
            self.get_translation('about_title'),
            self.get_translation('about_text')
        )

    def closeEvent(self, event):
        if self.dd_worker and self.dd_worker.isRunning():
            reply = QMessageBox.question(
                self,
                self.get_translation('app_closing_title'),
                self.get_translation('app_closing_msg'),
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No
            )
            if reply == QMessageBox.Yes:
                self.dd_worker.stop_flag = True 
                self.stop_destruction_process()
                self.dd_worker.wait(5000) 
                event.accept()
            else:
                event.ignore()
        else:
            event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = LinuxDiskDestroyer()
    window.show()
    sys.exit(app.exec())
