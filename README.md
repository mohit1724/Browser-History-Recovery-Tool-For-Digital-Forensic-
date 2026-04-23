# Browser-History-Recovery-Tool-For-Digital-Forensic-

A **Python GUI tool** to extract and export browsing history from **Google Chrome** and **Mozilla Firefox**.  
The tool supports filtering by date range and even attempts to recover **deleted browser history** using SQLite’s `.recover` feature.  
It outputs results both in the interface and as a **CSV file** for easy analysis.

---

## 🚀 Features

✅ Extract browsing history from:
- **Google Chrome**
- **Mozilla Firefox**

✅ Additional capabilities:
- Specify **start and end dates** for filtering results 
- **Export** history data to CSV files automatically  
- View results in a **user-friendly Tkinter GUI**  
- Optionally **recover deleted history (experimental)** using SQLite `.recover`  
- Works **offline**, no external API needed

---

## 🧠 How It Works

1. The script locates the default browser history databases:
   - Chrome → `AppData\Local\Google\Chrome\User Data\Default\History`
   - Firefox → `AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite`

2. It copies the database to a temporary directory to avoid access errors.

3. For Chrome, it optionally runs SQLite’s `.recover` to restore deleted entries.

4. The script queries relevant tables:
   - Chrome → `urls`
   - Firefox → `moz_places`

5. Results are filtered by optional **start** and **end** dates, then exported to a timestamped `.csv` file.

---

## 🖥️ GUI Preview

The interface includes:
- Browser selection dropdown  
- Start and End date input (format: `YYYY-MM-DD`)  
- “Include Deleted History” checkbox  
- Extract button  
- Scrollable text output box showing fetched history  



