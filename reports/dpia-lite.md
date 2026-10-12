# DPIA-lite — điền trong checkpoint 5

1. Loại dữ liệu và phân loại:
   - **Tất cả dữ liệu trong bài là dữ liệu tổng hợp (synthetic data)**, không chứa dữ liệu cá nhân hay thông tin nhạy cảm thật ngoài đời.
   - **Phân loại dữ liệu (Data Classification)**:
     - `public`: Tài liệu công cộng, hướng dẫn người dùng chung.
     - `internal`: Nội dung yêu cầu hỗ trợ và ticket thông thường trong thư mục `corpus/` (`ticket-*.md`).
     - `restricted`: Hồ sơ khách hàng lưu trong `data/customers.json`, chứa các trường định danh nhạy cảm gồm Số định danh cá nhân (CCCD 12 chữ số), Số tài khoản ngân hàng (STK), Số điện thoại liên hệ (SĐT), Email và danh sách ticket liên kết (`related_tickets`).

2. Mục đích xử lý và principal:
   - **Mục đích xử lý (`request_purpose`)**:
     - `summarize-tickets`: Tổng hợp danh sách và nội dung ticket còn mở trong kỳ để báo cáo vận hành.
     - `support-reply`: Hỗ trợ phản hồi và tra soát thông tin tài khoản cho khách hàng gắn với ticket cụ thể.
     - `privacy-audit`: Kiểm toán tuân thủ chính sách dữ liệu do cán bộ bảo vệ dữ liệu thực hiện.
   - **Principal mô phỏng (`data/principals.json`)**:
     - `support_l1`: Nhân viên hỗ trợ sơ cấp, chỉ có quyền `search_docs` phục vụ mục đích `summarize-tickets` hoặc `support-reply`. Bị cấm truy xuất `read_customer` (không được tiếp cận dữ liệu restricted).
     - `billing`: Nhân viên đối soát tài chính, được phép gọi `search_docs` và `read_customer` cho mục đích `summarize-tickets` và `billing-reconciliation`.
     - `dpo`: Chuyên viên bảo vệ dữ liệu (Data Protection Officer), có quyền `search_docs` và `read_customer` cho các mục đích tra soát và kiểm toán bảo mật.

3. Dữ liệu đi qua những run/tool nào, endpoint nào:
   - **Run A (Untrusted Context Boundary)**:
     - Nhận yêu cầu từ người dùng, gọi `tools.search_docs` nạp toàn bộ ticket trong `corpus/` (phân loại `internal`).
     - Chạy qua cổng `agent.pii.redact` để lọc bỏ các thực thể PII xuất hiện trong ngữ cảnh thô.
     - Trích xuất duy nhất danh sách ID ticket dạng số nguyên từ tên file (`ticket-(\d+).md`). Toàn bộ free text của tài liệu bị chặn lại tại Run A, ngăn ngừa prompt injection lây lan.
   - **Run B (Private Store Boundary - Trifecta Split)**:
     - Nhận danh sách ticket ID số từ Run A, tra cứu vào trường `related_tickets` trong `data/customers.json` để xác định đúng khách hàng hợp lệ.
     - Gọi `tools.read_customer` (phân loại `restricted`) sau khi được Policy Enforcement Point (PEP) thẩm định quyền của principal.
   - **Egress Endpoint**:
     - Endpoint sink mô phỏng: `http://127.0.0.1:10024/reconcile`.
     - Khi kẻ tấn công chèn lệnh yêu cầu gửi dữ liệu ra sink, PEP kích hoạt rule tối thiểu: cấm tuyệt đối egress (`egress_enabled=True`) đối với dữ liệu `restricted`, từ chối lệnh `http_post` và ghi log deny. Không có byte dữ liệu nào thoát ra ngoài máy cục bộ.

4. Bằng chứng deny/allow và giới hạn của mock:
   - **Bằng chứng Allow**:
     - `reports/ledger.jsonl`: Dòng 1 ghi nhận tool `search_docs` được allow cho principal `dpo`. Các dòng 2–22 ghi nhận tool `read_customer` được allow cho `dpo` khi phục vụ các ticket hợp lệ có khách hàng gắn kèm.
   - **Bằng chứng Deny**:
     - `reports/ledger.jsonl`: Dòng 23 ghi nhận tool `http_post` bị deny với lý do: `"Chính sách tối thiểu: Nghiêm cấm egress đối với dữ liệu classified restricted"`, gắn với `on_behalf_of: "dpo"`.
     - Trong test OBO (`tests/test_obo.py`), mọi nỗ lực của principal `support_l1` nhằm đọc `read_customer` đều bị deny với lý do tool không thuộc quyền được cấp.
     - `reports/attack-after.log`: Tệp rỗng (0 bytes), chứng minh PII không bị rò rỉ ra sink sau khi áp dụng containment.
   - **Giới hạn của Mock**:
     - `MockLLM` nhận diện injection dựa trên tập marker từ khóa và regex cố định, chỉ mô phỏng hành vi ngây thơ tuân theo chỉ thị của LLM; chưa mô phỏng được các vector tấn công phức tạp như multi-step jailbreak, prompt encoding (Base64/rot13) hoặc suy luận suy diễn nhiều bước.
     - Cơ chế OBO được kiểm tra thông qua mock fixture `principals.json`, chưa phải là hệ thống xác thực và cấp quyền hoàn chỉnh trong môi trường production (như SPIFFE/SPIRE, mTLS, OAuth2/OIDC token có chữ ký số).
