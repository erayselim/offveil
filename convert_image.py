from PIL import Image
import os

def convert_png_to_bmp(png_path, bmp_path):
    """PNG dosyasını BMP'ye çevirir."""
    try:
        if not os.path.exists(png_path):
            print(f"Error: Input file not found at {png_path}")
            return
            
        img = Image.open(png_path)
        img.save(bmp_path)
        
        if os.path.exists(bmp_path):
            print(f"Successfully converted {png_path} to {bmp_path}")
        else:
            print(f"Error: Conversion failed, output file not found at {bmp_path}")
            
    except Exception as e:
        print(f"An error occurred during conversion: {e}")

if __name__ == "__main__":
    convert_png_to_bmp("offveil.png", "offveil.bmp") 