# conftest.py
"""
Pytest configuration file
Помещается в корень проекта для правильных импортов
"""

import sys
import os

# Добавляем текущую директорию в Python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

import pytest

# Опционально: общие fixtures для всех тестов
@pytest.fixture(scope="session")
def project_root():
    """Корневая директория проекта"""
    return os.path.dirname(__file__)

@pytest.fixture(scope="session")
def model_path(project_root):
    """Путь к ML модели"""
    return os.path.join(project_root, "models", "sql_injection_model.pkl")