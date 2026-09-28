# MiniSOC

MiniSOC is a lightweight Security Operations Center dashboard built with Python, Flask, and SQLite.

It demonstrates a basic security monitoring pipeline:

```text
Security Log
     ↓
Log Parser
     ↓
Detection Engine
     ↓
Alert Deduplication
     ↓
SQLite Database
     ↓
SOC Dashboard
