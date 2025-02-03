import subprocess
import re
import sys
import os
import time
import argparse
import csv
from datetime import datetime
from typing import Dict, Optional

class HintlessSimplePIRRunner:
   def __init__(self, base_dir, rows: int = 1024, cols: int = 1024):
       self.base_dir = os.path.abspath(base_dir)
       self.rows = rows
       self.cols = cols
       self.env = os.environ.copy()
       self.env["PAGER"] = "cat"  # Prevent hanging on output

   def update_parameters_in_files(self) -> bool:
       file_path = os.path.join(self.base_dir, "hintless_simplepir/benchmark_parameters.h")
       
       if not os.path.exists(file_path):
           print(f"Cannot find parameters file at {file_path}")
           return False
           
       try:
           with open(file_path, 'r') as f:
               content = f.read()
           

           content = re.sub(r'#define\s+DB_ROWS\s+\d+', f'#define DB_ROWS {self.rows}', content)
           content = re.sub(r'#define\s+DB_COLS\s+\d+', f'#define DB_COLS {self.cols}', content)
           
           with open(file_path, 'w') as f:
               f.write(content)
           return True
       except Exception as e:
           print(f"Error updating parameters: {e}")
           return False

   def run_command(self, cmd):
       try:
           result = subprocess.run(
               cmd,
               capture_output=True,
               text=True,
               env=self.env,
               cwd=self.base_dir,
               shell=True
           )
           if result.returncode != 0:
               print(f"Command failed with error: {result.stderr}")
           return result.stdout
       except Exception as e:
           print(f"Error running command: {e}")
           return None

   def run_and_collect_metrics(self) -> Optional[Dict[str, float]]:
       if not self.update_parameters_in_files():
           return None

       build_cmd = "bazel build -c opt --cxxopt='-std=c++17' //hintless_simplepir:hintless_simplepir_test --cxxopt=\"-w\" --copt=\"-w\""
       self.run_command(build_cmd)

       cmd = "bazel run -c opt --cxxopt='-std=c++17' --noshow_progress //hintless_simplepir:hintless_simplepir_test --cxxopt=\"-w\" --copt=\"-w\""
       
       print(f"Running test with rows={self.rows}, cols={self.cols}...")
       output = self.run_command(cmd)
       if not output:
           print("Failed to run test")
           return None

       return self.parse_outputs(output)

   def parse_outputs(self, output):
       if not output:
           return None
           
       metrics = {}

       # Verify parameters were passed correctly
       rows_match = re.search(r'Rows in database: (\d+)', output)
       cols_match = re.search(r'Columns in database: (\d+)', output)
       
       if rows_match and cols_match:
           actual_rows = int(rows_match.group(1))
           actual_cols = int(cols_match.group(1))
           
           if actual_rows != self.rows or actual_cols != self.cols:
               print(f"Parameter mismatch!")
               print(f"Expected: rows={self.rows}, cols={self.cols}")
               print(f"Got: rows={actual_rows}, cols={actual_cols}")
               return None
           else:
               print(f"Parameters verified: rows={actual_rows}, cols={actual_cols}")

       # Save full run log
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       log_filename = f"hintless_run_log_{self.rows}_{self.cols}_{timestamp}.txt"
       with open(log_filename, 'w') as f:
           f.write(output)
       print(f"Full run log saved to {log_filename}")
           
       # Parse metrics from the output
       patterns = {
           'Global Prepr (S)': r'Global Prepr \(S\) : ([\d.]+)',
           'Server Per-Client Prepr (s)': r'Server Per-Client Prepr \(s\) : ([\d.]+)',
           'Client Local Prepr (s)': r'Client Local Prepr \(s\) : ([\d.]+)',
           'Client Prepa Pre Req (s)': r'Client Prepa Pre Req \(s\) : ([\d.]+)',
           'Server Prepa Comp (s)': r'Server Prepa Comp \(s\) : ([\d.]+)',
           'Client Prepa Post Req (s)': r'Client Prepa Post Req \(s\) : ([\d.]+)',
           'Query: Client Req Gen (ms)': r'Query: Client Req Gen \(ms\) : ([\d.]+)',
           'Query: Server Comp (s)': r'Query: Server Comp \(s\) : ([\d.]+)', 
           'Query: Client Decryption (ms)': r'Query: Client Decryption \(ms\) : ([\d.]+)',
           'Query: Client Verification (ms)': r'Query: Client Verification \(ms\) : ([\d.]+)',
           'Hints (MiB)': r'Hints \(MiB\) : ([\d.]+)',
           'Long Term State (KiB)': r'Long Term State \(KiB\) : ([\d.]+)',
           'Online State (KiB)': r'Online State \(KiB\) : ([\d.]+)',
           'Offline Up (KiB)': r'Offline Up \(KiB\) : ([\d.]+)',
           'Offline Down (KiB)': r'Offline Down \(KiB\) : ([\d.]+)',
           'Prep Up (Kib)': r'Prep Up \(Kib\) : ([\d.]+)',
           'Prep Down (KiB)': r'Prep Down \(KiB\) : ([\d.]+)',
           'Query Up (KiB)': r'Query Up \(KiB\) : ([\d.]+)',
           'Query Down (KiB)': r'Query Down \(KiB\) : ([\d.]+)'
       }
       
       for metric, pattern in patterns.items():
           match = re.search(pattern, output)
           if match:
               metrics[metric] = float(match.group(1))
           else:
               print(f"Warning: Could not find metric '{metric}' in output")
               
       parsed_metrics_file = f"hintless_parsed_metrics_{self.rows}_{self.cols}_{timestamp}.txt"
       with open(parsed_metrics_file, 'w') as f:
           f.write("Parsed Metrics:\n")
           for metric, value in metrics.items():
               f.write(f"{metric}: {value}\n")
           
       return metrics

def write_results_to_csv(results, filename=None):
   if not results:
       return
   
   if filename is None:
       timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
       filename = f"hintless_results_{timestamp}.csv"
   
   fieldnames = set(['rows', 'cols'])
   for result in results:
       fieldnames.update(result.keys())
   fieldnames = sorted(list(fieldnames))
   
   with open(filename, 'w', newline='') as csvfile:
       writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
       writer.writeheader()
       for result in results:
           writer.writerow(result)
   
   print(f"\nResults written to {filename}")
   
   summary_file =  os.path.splitext(filename)[0] + "_summary.txt"
   with open(summary_file, 'w') as f:
       f.write(f"HintlessSimplePIR Experiment Summary\n")
       f.write(f"Run at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
       for i, result in enumerate(results):
           f.write(f"\nConfiguration {i+1}:\n")
           f.write(f"Rows: {result['rows']}\n")
           f.write(f"Cols: {result['cols']}\n")
           f.write("Metrics:\n")
           for metric, value in result.items():
               if metric not in ['rows', 'cols']:
                   f.write(f"  {metric}: {value}\n")
                   
   print(f"Summary written to {summary_file}")

def batch_run(base_dir: str, configs: list) -> list:
   results = []
   
   for config in configs:
       print(f"\nRunning experiment with rows={config['rows']}, cols={config['cols']}")
       runner = HintlessSimplePIRRunner(base_dir, config['rows'], config['cols'])
       metrics = runner.run_and_collect_metrics()
       if metrics:
           metrics['rows'] = config['rows']
           metrics['cols'] = config['cols']
           results.append(metrics)
       else:
           print(f"Failed to collect metrics for rows={config['rows']}, cols={config['cols']}")
   
   return results

def main():
   parser = argparse.ArgumentParser(description='Run HintlessSimplePIR experiments')
   parser.add_argument('--rows', type=int, default=1024, help='Number of rows')
   parser.add_argument('--cols', type=int, default=1024, help='Number of columns')
   parser.add_argument('--batch', action='store_true', help='Run batch experiments')
   parser.add_argument('--output', type=str, help='Output CSV file name')
   args = parser.parse_args()

   hintlesspir_dir = os.path.expanduser("~/pir/hintless_pir")
   
   if not os.path.exists(hintlesspir_dir):
       print(f"HintlessVerifiablePIR directory not found at {hintlesspir_dir}")
       sys.exit(1)

   results = []
   if args.batch:
       configs = [
            # {'rows': 4096, 'cols': 2048},
            # {'rows': 16384, 'cols': 16384},
            # {'rows': 32768, 'cols': 16384},
            # {'rows': 32768, 'cols': 32768},
            {'rows': 65536, 'cols': 131072},
            {'rows': 131072, 'cols': 65536}
       ]
       results = batch_run(hintlesspir_dir, configs)
       
       print("\nBatch Results:")
       for result in results:
           print(f"\nrows={result['rows']}, cols={result['cols']}")
           for metric, value in result.items():
               if metric not in ['rows', 'cols']:
                   print(f"{metric}: {value}")
   else:
       runner = HintlessSimplePIRRunner(hintlesspir_dir, args.rows, args.cols)
       metrics = runner.run_and_collect_metrics()
       
       if metrics:
           metrics['rows'] = args.rows
           metrics['cols'] = args.cols
           results = [metrics]
           print("\nCollected Metrics:")
           for metric, value in metrics.items():
               print(f"{metric}: {value}")
       else:
           print("Failed to collect metrics")

   if results:
       write_results_to_csv(results, args.output)

if __name__ == "__main__":
   main()