# Task 1 — File Integrity Checker

How to run:
1. Create a test folder, e.g. C:\Users\ideal\Desktop\test_folder and add some files.
2. Create baseline:
   python file_integrity_checker.py baseline C:\Users\ideal\Desktop\test_folder baseline.json
3. Modify or add files in the folder, then compare:
   python file_integrity_checker.py compare C:\Users\ideal\Desktop\test_folder baseline.json
