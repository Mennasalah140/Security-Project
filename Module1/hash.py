import os
import hashlib
import argparse

def compute_file_hash(filepath, hash_algo=hashlib.sha256):
    """Compute the SHA-256 hash of a single file."""
    hash_obj = hash_algo()
    try:
        with open(filepath, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hash_obj.update(chunk)
    except Exception as e:
        print(f"Error hashing {filepath}: {e}")
        return None
    return hash_obj.hexdigest()

def compute_directory_hash(dirpath):
    """Compute a single SHA-256 hash for the entire directory, including file contents and structure."""
    file_hashes = []
    for root, _, files in os.walk(dirpath):
        for filename in files:
            filepath = os.path.join(root, filename)
            rel_path = os.path.relpath(filepath, dirpath)  # Get relative path
            file_hash = compute_file_hash(filepath)
            if file_hash:
                file_hashes.append((rel_path, file_hash))
    
    # Sort the file paths to ensure consistent order
    file_hashes.sort(key=lambda x: x[0])
    
    # Combine relative paths and their hashes into a single hash
    combined_hash = hashlib.sha256()
    for rel_path, file_hash in file_hashes:
        combined_hash.update(rel_path.encode())
        combined_hash.update(file_hash.encode())
    
    return combined_hash.hexdigest()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Compute SHA-256 hash of a directory")
    parser.add_argument("directory", help="Path to the directory")
    parser.add_argument("--output", help="File to save the hash (optional)")
    args = parser.parse_args()

    hash_value = compute_directory_hash(args.directory)
    if args.output:
        with open(args.output, "w") as f:
            f.write(hash_value)
        print(f"Hash saved to {args.output}")
    else:
        print(f"Directory hash: {hash_value}")