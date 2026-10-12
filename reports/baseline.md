# Baseline — điền trong checkpoint 1

1. Agent có identity mỗi run chưa? Dẫn file/hàm:
   Chưa có. Trong `agent/loop.py` tại hàm `_naive_loop(message, llm)` (dòng 27-54) và `run_once()` (dòng 57-76), agent thực thi mà không có cơ chế quản lý danh tính độc lập cho mỗi run. Không có `run_id`, `agent_id`, `on_behalf_of` (principal identity), cũng như không có session token, phạm vi quyền (scopes) hay thời hạn hiệu lực (`expires_at`).

2. Ai cho phép `http_post`? Dẫn file/hàm:
   Không có ai/thực thể nào cho phép. Trong `agent/loop.py` tại hàm `_naive_loop()` (dòng 44), agent tự động gọi trực tiếp `tools.http_post(injected.target_url, {"records": collected})` ngay khi `llm.find_injection()` phát hiện chỉ thị. Hoàn toàn thiếu vắng Policy Enforcement Point (PEP) hoặc kiểm tra policy để thẩm định và chặn egress cho dữ liệu restricted.

3. Nếu gửi sai PII ra sink, bằng chứng ở đâu? Dẫn file/hàm:
   Bằng chứng duy nhất nằm ở phía server nhận (sink) tại `sink/sink.py` trong hàm `make_handler()` (dòng 40-55), nơi request được ghi vào file `reports/sink.log`. Phía agent tại `agent/loop.py` trong hàm `_naive_loop()` hoàn toàn không có audit log hay tamper-evident ledger nào để ghi nhận việc truy xuất customer hay egress dữ liệu PII.
