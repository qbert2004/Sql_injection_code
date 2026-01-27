"""
CLI Interface для SQL Injection Protector AI Agent
Командная строка для управления агентом
"""

import argparse
import sys
import json
from pathlib import Path
from typing import List
import requests
from colorama import init, Fore, Style
from datetime import datetime

from sql_injection_detector import SQLInjectionAgent, train_initial_model
from train_model import train_and_evaluate, SQLInjectionDataset

# Инициализация colorama для Windows
init(autoreset=True)

# ============================================================================
# УТИЛИТЫ
# ============================================================================

def print_banner():
    """Печать баннера"""
    banner = f"""
{Fore.CYAN}╔═══════════════════════════════════════════════════════════════╗
║  {Fore.YELLOW}SQL INJECTION PROTECTOR AI AGENT{Fore.CYAN}                          ║
║  {Fore.GREEN}Полноценный AI агент для защиты от SQL инъекций{Fore.CYAN}           ║
╚═══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def print_success(message: str):
    """Печать успешного сообщения"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_error(message: str):
    """Печать ошибки"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")

def print_info(message: str):
    """Печать информации"""
    print(f"{Fore.BLUE}ℹ {message}{Style.RESET_ALL}")

def print_warning(message: str):
    """Печать предупреждения"""
    print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")

# ============================================================================
# КОМАНДЫ CLI
# ============================================================================

def cmd_analyze(args):
    """Анализ текста на SQL инъекции"""
    print_banner()
    print_info(f"Analyzing: {args.text}")

    if args.api:
        # Анализ через API
        try:
            response = requests.post(
                f"{args.api_url}/api/analyze",
                json={"text": args.text, "source": "cli"},
                timeout=10
            )
            response.raise_for_status()
            result = response.json()

            print("\n" + "="*70)
            print(f"{Fore.CYAN}РЕЗУЛЬТАТ АНАЛИЗА (через API):{Style.RESET_ALL}")
            print("="*70)
            print_result(result)

        except requests.RequestException as e:
            print_error(f"API Error: {e}")
            sys.exit(1)
    else:
        # Локальный анализ
        try:
            agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
            result = agent.analyze(args.text)

            print("\n" + "="*70)
            print(f"{Fore.CYAN}РЕЗУЛЬТАТ АНАЛИЗА (локально):{Style.RESET_ALL}")
            print("="*70)
            print_result({
                "is_malicious": result.is_malicious,
                "confidence": result.confidence,
                "detection_method": result.detection_method,
                "matched_patterns": result.matched_patterns,
                "risk_score": result.risk_score,
                "timestamp": result.timestamp
            })

        except Exception as e:
            print_error(f"Analysis error: {e}")
            sys.exit(1)

def print_result(result: dict):
    """Печать результата анализа"""
    if result['is_malicious']:
        print(f"{Fore.RED}Вредоносный: ДА{Style.RESET_ALL}")
    else:
        print(f"{Fore.GREEN}Вредоносный: НЕТ{Style.RESET_ALL}")

    print(f"Уверенность: {result['confidence']:.2%}")
    print(f"Метод детектирования: {result['detection_method']}")
    print(f"Риск-скор: {result['risk_score']:.2%}")

    if result['matched_patterns']:
        print(f"Совпавшие паттерны: {', '.join(result['matched_patterns'])}")

def cmd_train(args):
    """Обучение модели"""
    print_banner()
    print_info("Starting model training...")

    try:
        if args.simple:
            # Простое обучение
            print_info("Training simple model with default dataset...")
            train_initial_model("sql_injection_model.pkl")
            print_success("Simple model trained successfully!")
        else:
            # Продвинутое обучение
            print_info("Training advanced model with extended dataset...")
            train_and_evaluate("sql_injection_model.pkl")
            print_success("Advanced model trained successfully!")

    except Exception as e:
        print_error(f"Training error: {e}")
        sys.exit(1)

def cmd_test(args):
    """Интерактивное тестирование"""
    print_banner()
    print_info("Interactive testing mode. Type 'exit' to quit.")
    print()

    try:
        agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
    except:
        print_error("Model not found. Please train the model first: cli.py train")
        sys.exit(1)

    while True:
        try:
            text = input(f"{Fore.CYAN}Enter text to test:{Style.RESET_ALL} ").strip()

            if text.lower() == 'exit':
                print_info("Exiting...")
                break

            if not text:
                continue

            result = agent.analyze(text)

            print("\n" + "-"*70)
            if result.is_malicious:
                print(f"{Fore.RED}⚠ MALICIOUS DETECTED!{Style.RESET_ALL}")
            else:
                print(f"{Fore.GREEN}✓ Safe{Style.RESET_ALL}")

            print(f"Confidence: {result.confidence:.2%}")
            print(f"Risk Score: {result.risk_score:.2%}")
            print(f"Method: {result.detection_method}")

            if result.matched_patterns:
                print(f"Patterns: {', '.join(result.matched_patterns)}")

            print("-"*70 + "\n")

        except KeyboardInterrupt:
            print("\n")
            print_info("Exiting...")
            break
        except Exception as e:
            print_error(f"Error: {e}")

def cmd_benchmark(args):
    """Бенчмарк на тестовых данных"""
    print_banner()
    print_info("Running benchmark tests...")

    test_cases = [
        # (text, expected_malicious, description)
        ("john.doe@example.com", False, "Email address"),
        ("' OR '1'='1", True, "Classic SQL injection"),
        ("Product Name 123", False, "Product name"),
        ("admin' --", True, "Comment-based injection"),
        ("1' UNION SELECT * FROM users--", True, "UNION injection"),
        ("Normal search query", False, "Normal text"),
        ("'; DROP TABLE users--", True, "Destructive injection"),
        ("https://example.com", False, "URL"),
        ("1' AND SLEEP(5)--", True, "Time-based injection"),
        ("User feedback here", False, "User text"),
    ]

    try:
        agent = SQLInjectionAgent(ml_model_path="sql_injection_model.pkl")
    except:
        print_error("Model not found. Please train the model first.")
        sys.exit(1)

    correct = 0
    total = len(test_cases)

    print("\n" + "="*70)
    print(f"{Fore.CYAN}BENCHMARK RESULTS:{Style.RESET_ALL}")
    print("="*70)

    for text, expected, description in test_cases:
        result = agent.analyze(text)
        is_correct = result.is_malicious == expected

        if is_correct:
            correct += 1
            status = f"{Fore.GREEN}✓{Style.RESET_ALL}"
        else:
            status = f"{Fore.RED}✗{Style.RESET_ALL}"

        print(f"{status} {description:30} | Expected: {expected:5} | Got: {result.is_malicious:5} | Conf: {result.confidence:.2%}")

    print("="*70)
    accuracy = (correct / total) * 100
    print(f"Accuracy: {correct}/{total} ({accuracy:.1f}%)")

    if accuracy >= 90:
        print_success("Excellent performance!")
    elif accuracy >= 75:
        print_warning("Good performance, but could be better")
    else:
        print_error("Poor performance, consider retraining")

def cmd_server(args):
    """Запуск API сервера"""
    print_banner()
    print_info(f"Starting API server on port {args.port}...")

    try:
        import uvicorn
        from app import app

        uvicorn.run(
            app,
            host=args.host,
            port=args.port,
            log_level="info"
        )
    except Exception as e:
        print_error(f"Server error: {e}")
        sys.exit(1)

def cmd_status(args):
    """Проверка статуса сервера"""
    print_banner()
    print_info(f"Checking server status at {args.api_url}...")

    try:
        # Health check
        response = requests.get(f"{args.api_url}/health", timeout=5)
        response.raise_for_status()
        health = response.json()

        print(f"\n{Fore.GREEN}Server is ONLINE{Style.RESET_ALL}")
        print(f"Status: {health.get('status')}")
        print(f"Agent: {health.get('agent_status')}")

        # Metrics
        response = requests.get(f"{args.api_url}/metrics", timeout=5)
        if response.status_code == 200:
            metrics = response.json()
            print(f"\n{Fore.CYAN}METRICS:{Style.RESET_ALL}")
            print(f"Total Requests: {metrics.get('total_requests', 0)}")
            print(f"Blocked: {metrics.get('blocked_requests', 0)}")
            print(f"Block Rate: {metrics.get('block_rate', 0):.2%}")
            print(f"Uptime: {metrics.get('uptime_seconds', 0):.0f} seconds")

    except requests.ConnectionError:
        print_error("Cannot connect to server. Is it running?")
        sys.exit(1)
    except requests.RequestException as e:
        print_error(f"Request error: {e}")
        sys.exit(1)

def cmd_export_dataset(args):
    """Экспорт датасета"""
    print_banner()
    print_info("Exporting dataset...")

    dataset = SQLInjectionDataset()
    dataset.load_default_dataset()

    if args.augment:
        print_info("Augmenting dataset...")
        dataset.augment_data(factor=args.augment_factor)

    dataset.save_dataset(args.output)
    print_success(f"Dataset exported to {args.output}")

# ============================================================================
# MAIN
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="SQL Injection Protector AI Agent CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze "' OR '1'='1"           Analyze text locally
  %(prog)s analyze "text" --api            Analyze via API
  %(prog)s train                           Train advanced model
  %(prog)s train --simple                  Train simple model
  %(prog)s test                            Interactive testing
  %(prog)s benchmark                       Run benchmark tests
  %(prog)s server                          Start API server
  %(prog)s status                          Check server status
  %(prog)s export-dataset -o data.json     Export dataset
        """
    )

    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze text for SQL injection')
    analyze_parser.add_argument('text', help='Text to analyze')
    analyze_parser.add_argument('--api', action='store_true', help='Use API instead of local agent')
    analyze_parser.add_argument('--api-url', default='http://localhost:8000', help='API URL')

    # Train command
    train_parser = subparsers.add_parser('train', help='Train the ML model')
    train_parser.add_argument('--simple', action='store_true', help='Use simple training (faster)')

    # Test command
    test_parser = subparsers.add_parser('test', help='Interactive testing mode')

    # Benchmark command
    benchmark_parser = subparsers.add_parser('benchmark', help='Run benchmark tests')

    # Server command
    server_parser = subparsers.add_parser('server', help='Start API server')
    server_parser.add_argument('--host', default='0.0.0.0', help='Host to bind')
    server_parser.add_argument('--port', type=int, default=8000, help='Port to bind')

    # Status command
    status_parser = subparsers.add_parser('status', help='Check server status')
    status_parser.add_argument('--api-url', default='http://localhost:8000', help='API URL')

    # Export dataset command
    export_parser = subparsers.add_parser('export-dataset', help='Export training dataset')
    export_parser.add_argument('-o', '--output', default='dataset.json', help='Output file')
    export_parser.add_argument('--augment', action='store_true', help='Augment dataset')
    export_parser.add_argument('--augment-factor', type=int, default=3, help='Augmentation factor')

    args = parser.parse_args()

    if not args.command:
        print_banner()
        parser.print_help()
        sys.exit(0)

    # Dispatch to command handlers
    command_handlers = {
        'analyze': cmd_analyze,
        'train': cmd_train,
        'test': cmd_test,
        'benchmark': cmd_benchmark,
        'server': cmd_server,
        'status': cmd_status,
        'export-dataset': cmd_export_dataset,
    }

    handler = command_handlers.get(args.command)
    if handler:
        handler(args)
    else:
        print_error(f"Unknown command: {args.command}")
        sys.exit(1)

if __name__ == "__main__":
    main()
