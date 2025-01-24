Если вы столкнетесь с ошибкой выполнения скрипта из-за политики безопасности, выполните следующую команду в PowerShell: Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

Чтобы запустить скрипт, откройте PowerShell и выполните: .\updateUsers.ps1





Автоматизация через Task Scheduler
Чтобы скрипт выполнялся каждый час автоматически:

Откройте Task Scheduler (Планировщик заданий).
Создайте новое задание:
Trigger: Раз в час.
Action: Запустить PowerShell с аргументами:

powershell.exe -ExecutionPolicy Bypass -File "C:\Path\To\updateUsers.ps1"