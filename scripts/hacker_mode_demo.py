#!/usr/bin/env python3
import sqlite3
import os
import sys

# Tìm file CSDL, hỗ trợ chạy từ thư mục gốc hoặc thư mục scripts
DB_PATH = "cloud_db.sqlite"
if not os.path.exists(DB_PATH):
    parent_db = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "cloud_db.sqlite")
    if os.path.exists(parent_db):
        DB_PATH = parent_db
    else:
        print("❌ Error: Không tìm thấy file Database 'cloud_db.sqlite'!")
        sys.exit(1)

def main():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    try:
        cursor.execute("SELECT COUNT(*) FROM encrypted_products")
    except sqlite3.OperationalError:
        print("❌ Error: Table 'encrypted_products' không tồn tại. Hãy chắc chắn Server đã chạy và có dữ liệu.")
        sys.exit(1)

    original_backups = {} # Lưu trạng thái {id: original_enc_price} để khôi phục

    while True:
        print("\n===========================================================")
        print("    💀 HACKER MODE - INTERACTIVE TERMINAL 💀")
        print("===========================================================")
        print("1. [View] Xem trộm CSDL (Data Dumping)")
        print("2. [Attack] Phá hoại dữ liệu (Data Tampering)")
        print("3. [Restore] Khôi phục dữ liệu gốc (Restore Database)")
        print("4. [Exit] Thoát (Tự động khôi phục dữ liệu trước khi thoát)")
        print("===========================================================")
        
        choice = input("\n👉 Chọn thao tác (1-4): ").strip()
        
        if choice == '1':
            cursor.execute("SELECT id, name, encrypted_price FROM encrypted_products LIMIT 5")
            rows = cursor.fetchall()
            print("\n--- DUMPED DATA (Top 5) ---")
            for r in rows:
                prod_id, name, enc_price = r
                truncated = enc_price[:30] + "......" + enc_price[-30:] if len(enc_price) > 60 else enc_price
                print(f"[{prod_id}] {name:<25} | {truncated}")
            print("---------------------------")
            print("💡 Phân tích: Hacker hoàn toàn KHÔNG THỂ đọc được giá thật của sản phẩm!")
                
        elif choice == '2':
            prod_id = input("Nhập ID sản phẩm muốn phá hoại (VD: 1, 2, 3...): ").strip()
            if not prod_id.isdigit():
                print("❌ ID không hợp lệ!")
                continue
                
            try:
                cursor.execute("SELECT name, encrypted_price FROM encrypted_products WHERE id = ?", (prod_id,))
                target = cursor.fetchone()
                if target:
                    name, orig_price = target
                    # Backup trước khi phá hoại
                    if prod_id not in original_backups:
                        original_backups[prod_id] = orig_price
                        
                    tampered_price = "999999999999999999999999999999999999999999999999999999999999999"
                    cursor.execute("UPDATE encrypted_products SET encrypted_price = ? WHERE id = ?", (tampered_price, prod_id))
                    conn.commit()
                    print(f"\n✅ [THÀNH CÔNG] Hacker đã phá hoại giá của '{name}' (ID: {prod_id})!")
                    print("🎮 LỜI KHUYÊN DEMO: Bây giờ hãy mở Web UI lên, bấm F5 hoặc tính 'Tổng Đồng Cấu'. Bạn sẽ thấy hệ thống văng lỗi vì phát hiện dữ liệu bất thường!")
                else:
                    print(f"❌ Không tìm thấy sản phẩm với ID {prod_id}")
            except Exception as e:
                print(f"Lỗi: {e}")
                
        elif choice == '3':
            if not original_backups:
                print("\nℹ️ Chưa có dữ liệu nào bị phá hoại, không cần khôi phục.")
            else:
                for pid, orig_price in original_backups.items():
                    cursor.execute("UPDATE encrypted_products SET encrypted_price = ? WHERE id = ?", (orig_price, pid))
                conn.commit()
                original_backups.clear()
                print("\n✅ Đã khôi phục toàn bộ CSDL về trạng thái an toàn ban đầu!")
                print("👉 Bạn có thể qua Web UI để thao tác bình thường.")
                
        elif choice == '4':
            if original_backups:
                for pid, orig_price in original_backups.items():
                    cursor.execute("UPDATE encrypted_products SET encrypted_price = ? WHERE id = ?", (orig_price, pid))
                conn.commit()
                print("\n✅ Đã tự động khôi phục CSDL an toàn trước khi thoát.")
            print("\nĐã thoát Hacker Mode. Chúc bạn demo thành công! 🚀")
            break
        else:
            print("❌ Lựa chọn không hợp lệ, vui lòng chọn từ 1 đến 4!")

if __name__ == "__main__":
    main()
