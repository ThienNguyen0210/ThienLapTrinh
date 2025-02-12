<?php
include 'db.php';

header("Content-Type: application/json");

$data = json_decode(file_get_contents("php://input"), true);

if (!isset($data['username']) || !isset($data['password'])) {
    echo json_encode(["success" => false, "message" => "Dữ liệu không hợp lệ!"]);
    exit();
}

$username = $conn->real_escape_string($data['username']);
$password = $data['password'];

$query = "SELECT id, password FROM users WHERE username = ?";
$stmt = $conn->prepare($query);
$stmt->bind_param("s", $username);
$stmt->execute();
$stmt->store_result();
$stmt->bind_result($userId, $hashedPassword);
$stmt->fetch();

if ($stmt->num_rows > 0 && password_verify($password, $hashedPassword)) {
    echo json_encode(["success" => true, "message" => "Đăng nhập thành công!", "user_id" => $userId]);
} else {
    echo json_encode(["success" => false, "message" => "Sai tài khoản hoặc mật khẩu!"]);
}

$stmt->close();
$conn->close();
?>
