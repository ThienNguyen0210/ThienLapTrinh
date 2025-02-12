<?php
include 'db.php';

header("Content-Type: application/json");

$data = json_decode(file_get_contents("php://input"), true);

if (!isset($data['username']) || !isset($data['password'])) {
    echo json_encode(["success" => false, "message" => "Dữ liệu không hợp lệ!"]);
    exit();
}

$username = $conn->real_escape_string($data['username']);
$password = password_hash($data['password'], PASSWORD_BCRYPT);

// Kiểm tra username đã tồn tại chưa
$checkQuery = "SELECT id FROM users WHERE username = ?";
$stmt = $conn->prepare($checkQuery);
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    echo json_encode(["success" => false, "message" => "Tên tài khoản đã tồn tại!"]);
    $stmt->close();
    $conn->close();
    exit();
}

$stmt->close();

// Chèn dữ liệu vào database
$insertQuery = "INSERT INTO users (username, password) VALUES (?, ?)";
$stmt = $conn->prepare($insertQuery);
$stmt->bind_param("ss", $username, $password);

if ($stmt->execute()) {
    echo json_encode(["success" => true, "message" => "Đăng ký thành công!"]);
} else {
    echo json_encode(["success" => false, "message" => "Lỗi khi đăng ký!"]);
}

$stmt->close();
$conn->close();
?>
