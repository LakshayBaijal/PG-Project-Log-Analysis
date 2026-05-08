import os

def split_log_file(input_file, chunk_size_mb=30):
    chunk_size_bytes = chunk_size_mb * 1024 * 1024
    file_number = 1
    current_size = 0
    output_file = None

    print(f"Splitting {input_file} into {chunk_size_mb}MB chunks...")

    try:
        with open(input_file, 'r', encoding='utf-8', errors='ignore') as infile:
            for line in infile:
                if output_file is None:
                    output_filename = f"{os.path.splitext(input_file)[0]}_part{file_number}.log"
                    output_file = open(output_filename, 'w', encoding='utf-8')
                
                output_file.write(line)
                current_size += len(line.encode('utf-8'))

                # When chunk size is reached, close current file to start a new one
                if current_size >= chunk_size_bytes:
                    output_file.close()
                    output_file = None
                    current_size = 0
                    file_number += 1

        if output_file:
            output_file.close()
            
        print(f"Success: File split into {file_number} parts.")
            
    except FileNotFoundError:
        print(f"Error: {input_file} not found. Please check the file path.")

if __name__ == "__main__":
    # Adjust this path if your log file is in a different location
    log_file_path = "snmptrap-20250522.log" 
    split_log_file(log_file_path, 30)