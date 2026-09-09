@echo off
chcp 65001 >nul
title its_4_s3cr3_t

:: Detectar si hay entorno virtual local
if exist "%~dp0.venv\Scripts\python.exe" (
    set PYTHON="%~dp0.venv\Scripts\python.exe"
) else (
    set PYTHON=python
)

%PYTHON% "%~dp0run.py" %*
