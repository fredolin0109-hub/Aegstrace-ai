"""
AEGISTRACE Browser Extension Packager
Builds a production-ready .zip archive suitable for Chrome Web Store upload
or manual offline deployment.
"""
import os
import zipfile

def package_extension():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    dist_dir = os.path.join(base_dir, "dist")
    os.makedirs(dist_dir, exist_ok=True)
    zip_path = os.path.join(dist_dir, "aegistrace-extension-v1.0.0.zip")

    include_items = ["manifest.json", "README.md", "icons", "src"]
    exclude_extensions = {".pyc", ".pyo", ".pyd"}
    exclude_dirs = {"__pycache__", ".pytest_cache", ".git"}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for item in include_items:
            item_path = os.path.join(base_dir, item)
            if os.path.isfile(item_path):
                zf.write(item_path, item)
                print(f"Added file: {item}")
            elif os.path.isdir(item_path):
                for root, dirs, files in os.walk(item_path):
                    dirs[:] = [d for d in dirs if d not in exclude_dirs]
                    for file in files:
                        ext = os.path.splitext(file)[1].lower()
                        if ext in exclude_extensions:
                            continue
                        file_path = os.path.join(root, file)
                        arcname = os.path.relpath(file_path, base_dir)
                        zf.write(file_path, arcname)
                        print(f"Added file: {arcname}")

    file_size_kb = os.path.getsize(zip_path) / 1024
    print(f"\n[SUCCESS] Extension packaged successfully: {zip_path} ({file_size_kb:.1f} KB)")
    return zip_path

if __name__ == "__main__":
    package_extension()
