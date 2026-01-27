"""
БЫСТРЫЙ ТЕСТ API - для клиентов
Простые примеры использования API
"""

import requests
from colorama import Fore, Style, init

init(autoreset=True)

API_URL = "http://localhost:8080"

def test_example(text, description):
    """Тест одного примера"""
    print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}Тест: {description}{Style.RESET_ALL}")
    print(f"Текст: {Fore.WHITE}{text}{Style.RESET_ALL}")

    try:
        response = requests.post(
            f"{API_URL}/api/analyze",
            json={"text": text},
            timeout=10
        )

        if response.status_code == 200:
            result = response.json()

            if result['is_malicious']:
                print(f"\n{Fore.RED}[!] ОБНАРУЖЕНА SQL ИНЪЕКЦИЯ!{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.GREEN}[+] Безопасно{Style.RESET_ALL}")

            print(f"Уверенность: {result['confidence']:.1%}")
            print(f"Риск-скор: {result['risk_score']:.1%}")
            print(f"Метод: {result['detection_method']}")

            if result['matched_patterns']:
                print(f"Паттерны: {', '.join(result['matched_patterns'][:3])}")

        else:
            print(f"{Fore.RED}Ошибка: {response.status_code}{Style.RESET_ALL}")

    except Exception as e:
        print(f"{Fore.RED}Ошибка: {e}{Style.RESET_ALL}")

print(f"""
{Fore.CYAN}============================================================
  БЫСТРЫЙ ТЕСТ SQL INJECTION PROTECTOR AI AGENT
============================================================{Style.RESET_ALL}
""")

# Примеры для теста
print(f"{Fore.GREEN}ТЕСТ 1: Вредоносные запросы{Style.RESET_ALL}")

test_example(
    "' OR '1'='1",
    "Классическая SQL инъекция"
)

test_example(
    "admin' --",
    "Инъекция с комментарием"
)

test_example(
    "1' UNION SELECT * FROM users--",
    "UNION-based атака"
)

test_example(
    "'; DROP TABLE users; --",
    "Деструктивная команда"
)

print(f"\n\n{Fore.GREEN}ТЕСТ 2: Безопасные данные{Style.RESET_ALL}")

test_example(
    "john.doe@example.com",
    "Email адрес"
)

test_example(
    "iPhone 15 Pro",
    "Название продукта"
)

test_example(
    "Отличный товар!",
    "Отзыв клиента"
)

print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
print(f"\n{Fore.GREEN}[+] Тест завершен!{Style.RESET_ALL}")
print(f"\n{Fore.YELLOW}Полная демонстрация: python demo_for_clients.py{Style.RESET_ALL}")
print(f"{Fore.YELLOW}API документация: http://localhost:8080/docs{Style.RESET_ALL}\n")
