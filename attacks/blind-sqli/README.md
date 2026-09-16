# ⏱️ Kỹ thuật Khai thác: Blind SQL Injection

## 1. Bản chất Lỗ hổng
Trong nhiều tình huống thực tế, máy chủ web tắt chế độ debug, không in thông báo lỗi SQL ra ngoài (vô hiệu hóa Error-based) và cũng không in dữ liệu từ bảng truy vấn tự do (vô hiệu hóa Union-based).

Khi đó, ta sử dụng **Blind SQL Injection (SQL Injection "mù")**:
- **Boolean-based Blind**: Dựa vào sự khác biệt trong nội dung trang web trả về khi điều kiện kiểm tra là `TRUE` (có hiển thị sản phẩm) hoặc `FALSE` (trang kết quả trắng / 0 sản phẩm).
- **Time-based Blind**: Yêu cầu cơ sở dữ liệu tạm dừng thực thi trong một số giây nhất định (sử dụng hàm `SLEEP(n)`) nếu biểu thức kiểm tra là `TRUE`. Nếu máy chủ phản hồi chậm trễ đúng bằng thời gian đó, kẻ tấn công kết luận giả thiết là đúng.

## 2. Công thức Khai thác Time-based trên MySQL
Mô hình câu lệnh:
```sql
IF(<Biểu thức kiểm tra điều kiện>, SLEEP(<số giây>), 0)
```
Ví dụ:
Kiểm tra xem ký tự thứ 1 của tên cơ sở dữ liệu có mã ASCII là 115 (ký tự `'s'`) hay không:
```sql
' AND IF(ASCII(SUBSTRING(database(), 1, 1)) = 115, SLEEP(3), 0) -- 
```
- Nếu đúng (ký tự `'s'`), MySQL thực thi `SLEEP(3)`, toàn bộ HTTP response bị trễ > 3.000 ms.
- Nếu sai, MySQL trả về ngay lập tức (< 100 ms).

## 3. Tối ưu hóa Tốc độ bằng Thuật toán Tìm kiếm Nhị phân (Binary Search)
Thay vì thử tuần tự từng ký tự từ mã 32 đến 126 (mất tới 95 requests cho 1 ký tự), ta sử dụng thuật toán **Binary Search**:
1. So sánh lớn hơn: `ASCII(...) > 79`
2. Chia đôi không gian tìm kiếm.
3. Chỉ mất tối đa `ceil(log2(95)) = 7` requests để xác định chính xác một ký tự!

## 4. Chạy Script khai thác tự động
```bash
python blind_extractor.py
```
Script cung cấp tùy chọn vét dữ liệu bằng cả hai cơ chế: Time-based và Boolean-based.
