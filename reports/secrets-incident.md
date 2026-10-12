# Secret giả trong lịch sử Git — điền trong checkpoint 4

- Scanner và phiên bản: Gitleaks v8.30.1
- Commit chứa token giả: `1bdd849` (1bdd849922156c868a5ee9293d68f5b72e242d2c)
- File, rule và kết quả quét lịch sử:
  - File: `lab-fake-secret.txt`
  - Rule ID: `lab24-synthetic-token` (Regex: `LAB24_FAKE_TOKEN=LAB24-DEMO-[A-Z0-9]{16}`)
  - Kết quả quét lịch sử bằng `gitleaks git --config .gitleaks.toml --redact --verbose .`: Phát hiện 1 leak tại commit `1bdd849`, dòng 1 trong file `lab-fake-secret.txt`.
- Kết quả quét file hiện tại:
  - Quét bằng `gitleaks dir --config .gitleaks.toml --verbose .`: 0 leaks found (sạch, không có secret nào ở HEAD).
- Nếu đây là credential thật, cần xử lý thế nào:
  - Phải lập tức thu hồi (revoke) và rotate secret tại nhà cung cấp dịch vụ/hệ thống cấp phát credential ngay lập tức.
  - Kiểm tra audit log của credential để xác định xem secret đã bị kẻ tấn công lợi dụng để truy cập trái phép hay chưa (incident investigation).
  - Viết lại lịch sử Git (sử dụng git-filter-repo hoặc BFG Repo-Cleaner) để loại bỏ blob chứa secret khỏi mọi ref và commit history, sau đó force-push và thông báo toàn bộ dev clone lại repo.
- Vì sao xoá file khỏi HEAD hoặc pin dependency vẫn chưa đủ:
  - Xoá file khỏi HEAD chỉ làm file biến mất ở commit mới; secret vẫn tồn tại vĩnh viễn trong commit cũ của lịch sử Git (`git log`/`git show` vẫn xem được toàn bộ nội dung). Bất kỳ ai clone hoặc pull repo đều có thể trích xuất secret này.
  - Pin dependency và pre-commit hook chỉ bảo vệ chuỗi cung ứng khỏi việc tải package lạ hoặc ngăn chặn secret mới bị commit vào codebase trong tương lai, chứ không thể vô hiệu hóa credential đã từng bị lộ ra bên ngoài.
  - Do đó, bước thu hồi và rotate credential tại server/nhà cung cấp là bắt buộc và không thể thay thế.
