import base64
from PIL import Image, ImageTk
from io import BytesIO
import tkinter as tk
from tkinter import messagebox, scrolledtext

def decode_qr():
    try:
        # Get Base64 input from text box
        base64_qr = text_input.get("1.0", tk.END).strip()

        if not base64_qr:
            messagebox.showwarning("Warning", "Please enter a Base64 string.")
            return

        # Decode Base64 string
        img_data = base64.b64decode(base64_qr)
        
        # Convert to an image
        img = Image.open(BytesIO(img_data))

        # Convert to Tkinter-compatible image
        img_tk = ImageTk.PhotoImage(img)

        # Display the image in the GUI
        label_img.config(image=img_tk)
        label_img.image = img_tk  # Keep a reference to avoid garbage collection

    except Exception as e:
        messagebox.showerror("Error", f"❌ Failed to decode QR Code: {e}")

# Create the GUI window
root = tk.Tk()
root.title("QR Code Decoder")
root.geometry("500x600")

# Label
label = tk.Label(root, text="📌 Enter Base64 QR Code:", font=("Arial", 12))
label.pack(pady=10)

# Text input for Base64
text_input = scrolledtext.ScrolledText(root, height=8, width=50, wrap=tk.WORD)
text_input.pack(pady=10)

# Decode button
btn_decode = tk.Button(root, text="Decode QR Code", command=decode_qr, font=("Arial", 12), bg="blue", fg="white")
btn_decode.pack(pady=10)

# Label for displaying the QR Code
label_img = tk.Label(root)
label_img.pack(pady=10)


root.mainloop()
