import os
import sqlite3
import shutil
import tempfile
from datetime import datetime, timedelta
import csv
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

def chrome_time_to_datetime(chrome_time):
    return datetime(1601, 1, 1) + timedelta(microseconds=chrome_time)

def write_to_csv(data, filename):
    with open(filename, mode='w', newline='', encoding='utf-8') as file:
        writer = csv.writer(file)
        writer.writerow(["Title", "URL", "Last Visited"])
        writer.writerows(data)

def recover_deleted_sqlite_data(original_db_path, recovered_db_path):
    try:
        # Run `.recover` command
        result = subprocess.run(
            ["sqlite3", original_db_path, ".recover"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            return None, f"Failed to recover deleted data: {result.stderr}"

        # Write recovered SQL to a temp file
        sql_path = os.path.splitext(recovered_db_path)[0] + "_recovered.sql"
        with open(sql_path, "w", encoding="utf-8") as f:
            f.write(result.stdout)

        # Create a new database from the recovered SQL
        conn = sqlite3.connect(recovered_db_path)
        cursor = conn.cursor()
        cursor.executescript(result.stdout)
        conn.commit()
        conn.close()
        return recovered_db_path, None
    except Exception as e:
        return None, str(e)

def get_chrome_history(start_date=None, end_date=None, include_deleted=False):
    original_path = os.path.expanduser("~") + r"\AppData\Local\Google\Chrome\User Data\Default\History"
    if not os.path.exists(original_path):
        return "Chrome history database not found!\n"

    try:
        temp_dir = tempfile.gettempdir()
        temp_copy = os.path.join(temp_dir, "History_copy")
        shutil.copy2(original_path, temp_copy)

        if include_deleted:
            recovered_db = os.path.join(temp_dir, "History_recovered.db")
            recovered_path, error = recover_deleted_sqlite_data(temp_copy, recovered_db)
            if error:
                return f"Could not recover deleted history: {error}"
            db_path = recovered_path
        else:
            db_path = temp_copy

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT url, title, last_visit_time FROM urls ORDER BY last_visit_time DESC")
        results = cursor.fetchall()
        filtered_results = []

        for url, title, last_visit_time in results:
            visit_time = chrome_time_to_datetime(last_visit_time)
            if start_date and visit_time < start_date:
                continue
            if end_date and visit_time > end_date:
                continue
            filtered_results.append([title, url, visit_time.strftime("%Y-%m-%d %H:%M:%S")])

        filename = f"chrome_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        write_to_csv(filtered_results, filename)

        output = ""
        for row in filtered_results:
            output += f"Title: {row[0]}\nURL: {row[1]}\nLast Visited: {row[2]}\n\n"

        conn.close()
        return output + f"Chrome history exported to '{filename}'.\n"
    except Exception as e:
        with open("error_log.txt", "a") as f:
            f.write(f"[{datetime.now()}] Chrome Error: {e}\n")
        return "Error accessing Chrome history database. Check error_log.txt\n"

def get_firefox_history(start_date=None, end_date=None):
    firefox_profile_path = os.path.expanduser("~") + r"\AppData\Roaming\Mozilla\Firefox\Profiles"
    if not os.path.exists(firefox_profile_path):
        return "Firefox profile not found!\n"

    for root, dirs, files in os.walk(firefox_profile_path):
        for file in files:
            if file == "places.sqlite":
                history_db_path = os.path.join(root, file)
                try:
                    conn = sqlite3.connect(history_db_path)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url, title, last_visit_date FROM moz_places ORDER BY last_visit_date DESC")
                    results = cursor.fetchall()
                    filtered_results = []

                    for url, title, last_visit_date in results:
                        if last_visit_date:
                            visit_time = datetime.fromtimestamp(last_visit_date / 1_000_000)
                            if start_date and visit_time < start_date:
                                continue
                            if end_date and visit_time > end_date:
                                continue
                            filtered_results.append([title, url, visit_time.strftime("%Y-%m-%d %H:%M:%S")])

                    filename = f"firefox_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
                    write_to_csv(filtered_results, filename)

                    output = ""
                    for row in filtered_results:
                        output += f"Title: {row[0]}\nURL: {row[1]}\nLast Visited: {row[2]}\n\n"

                    conn.close()
                    return output + f"Firefox history exported to '{filename}'.\n"
                except Exception as e:
                    with open("error_log.txt", "a") as f:
                        f.write(f"[{datetime.now()}] Firefox Error: {e}\n")
                    return "Error accessing Firefox history database. Check error_log.txt\n"
    return "Firefox history database not found!\n"

def parse_date(date_str):
    try:
        return datetime.strptime(date_str, "%Y-%m-%d") if date_str else None
    except ValueError:
        messagebox.showerror("Date Error", f"Invalid date: {date_str}. Use YYYY-MM-DD format.")
        return None

def run_extraction():
    browser = browser_choice.get()
    start = parse_date(start_date.get())
    end = parse_date(end_date.get())
    if start and end and start > end:
        messagebox.showerror("Date Error", "Start date cannot be after end date.")
        return

    if browser == "Chrome":
        output = get_chrome_history(start, end, include_deleted.get())
    elif browser == "Firefox":
        output = get_firefox_history(start, end)
    else:
        output = "Please select a valid browser."
    result_text.delete(1.0, tk.END)
    result_text.insert(tk.END, output)

# GUI Setup
root = tk.Tk()
root.title("Browser History Extractor")
root.geometry("700x540")

ttk.Label(root, text="Select Browser:").pack(pady=5)
browser_choice = ttk.Combobox(root, values=["Chrome", "Firefox"])
browser_choice.pack()

ttk.Label(root, text="Start Date (YYYY-MM-DD):").pack(pady=5)
start_date = ttk.Entry(root)
start_date.pack()

ttk.Label(root, text="End Date (YYYY-MM-DD):").pack(pady=5)
end_date = ttk.Entry(root)
end_date.pack()

include_deleted = tk.BooleanVar()
ttk.Checkbutton(root, text="Include Deleted History (Experimental)", variable=include_deleted).pack(pady=5)

ttk.Button(root, text="Extract History", command=run_extraction).pack(pady=10)

result_text = scrolledtext.ScrolledText(root, width=80, height=20)
result_text.pack(pady=10)

root.mainloop()
