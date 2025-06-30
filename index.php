<?php
session_start();

// Add database connection
require_once 'dbcon.php';

// Redirect to login if not logged in
if (!isset($_SESSION['user_email'])) {
    header('Location: login.php');
    exit();
}

// Handle file upload
$message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (isset($_FILES['userfile']) && isset($_POST['filename'])) {
        $uploadDir = __DIR__ . '/uploads/';
        if (!is_dir($uploadDir)) {
            mkdir($uploadDir, 0777, true);
        }
        $originalName = basename($_FILES['userfile']['name']);
        $fileType = pathinfo($originalName, PATHINFO_EXTENSION);
        $allowedTypes = ['txt', 'jpg', 'jpeg', 'png', 'gif'];

        if (in_array(strtolower($fileType), $allowedTypes)) {
            $safeName = preg_replace('/[^a-zA-Z0-9_\-\.]/', '_', $_POST['filename']);
            $targetFile = $uploadDir . $safeName . '.' . $fileType;
            if (move_uploaded_file($_FILES['userfile']['tmp_name'], $targetFile)) {
                // Save file info to database
                $stmt = $conn->prepare("INSERT INTO files (user_id, filename, stored_name, file_type) VALUES (?, ?, ?, ?)");
                $userId = $_SESSION['user_id'];
                $storedName = $safeName . '.' . $fileType;
                $stmt->bind_param("isss", $userId, $originalName, $storedName, $fileType);
                $stmt->execute();
                $message = "File uploaded successfully!";
            } else {
                $message = "Error uploading file.";
            }
        } else {
            $message = "Invalid file type. Only text and image files are allowed.";
        }
    } else {
        $message = "Please provide a file name and select a file.";
    }
}

// Fetch all uploaded files for this user
$userId = $_SESSION['user_id'];
$result = $conn->prepare("SELECT * FROM files WHERE user_id = ? ORDER BY uploaded_at DESC");
$result->bind_param("i", $userId);
$result->execute();
$files = $result->get_result();
?>

<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>File Storage App</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <div class="container">
        <div class="logout-link">
            <a href="logout.php">Logout</a>
        </div>
        <h2>Welcome, <?php echo htmlspecialchars($_SESSION['user_email']); ?>!</h2>
        <h3>Store a File</h3>
        <?php if ($message): ?>
            <div class="<?php echo strpos($message, 'success') !== false ? 'message' : 'error'; ?>">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>
        <form method="post" enctype="multipart/form-data" autocomplete="off">
            <div class="form-group">
                <label for="filename">File Name:</label>
                <input type="text" name="filename" id="filename" required>
            </div>
            <div class="form-group">
                <label for="userfile">Select file (txt, jpg, jpeg, png, gif):</label>
                <input type="file" name="userfile" id="userfile" required>
            </div>
            <input type="submit" value="Upload">
        </form>

        <h3>Your Uploaded Files</h3>
        <table style="width:100%;margin-top:20px;">
            <tr>
                <th>File Name</th>
                <th>Type</th>
                <th>Uploaded At</th>
                <th>Download</th>
            </tr>
            <?php while ($row = $files->fetch_assoc()): ?>
                <tr>
                    <td><?php echo htmlspecialchars($row['filename']); ?></td>
                    <td><?php echo htmlspecialchars($row['file_type']); ?></td>
                    <td><?php echo htmlspecialchars($row['uploaded_at']); ?></td>
                    <td>
                        <a href="uploads/<?php echo urlencode($row['stored_name']); ?>" download>Download</a>
                    </td>
                </tr>
            <?php endwhile; ?>
        </table>
    </div>
    <script src="script.js"></script>
</body>
</html>