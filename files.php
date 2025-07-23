<?php
session_start();
require_once 'dbcon.php';

if (!isset($_SESSION['user_id'])) {
    die('Access denied.');
}

$userId = $_SESSION['user_id'];
$folderId = isset($_GET['folder_id']) ? (int)$_GET['folder_id'] : 0;

// Get files from DB
$stmt = $conn->prepare("SELECT * FROM files WHERE user_id = ? AND folder_id = ? ORDER BY uploaded_at DESC");
$stmt->bind_param("ii", $userId, $folderId);
$stmt->execute();
$files = $stmt->get_result();

// Rename file handler
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rename_file_id'], $_POST['rename_file_name'])) {
    $fileId = (int)$_POST['rename_file_id'];
    $newName = trim($_POST['rename_file_name']);

    if ($newName !== '') {
        // Get current file info
        $stmtFile = $conn->prepare("SELECT stored_name FROM files WHERE id = ? AND user_id = ?");
        $stmtFile->bind_param("ii", $fileId, $userId);
        $stmtFile->execute();
        $result = $stmtFile->get_result();

        if ($result->num_rows === 1) {
            $file = $result->fetch_assoc();
            $storedName = $file['stored_name'];
            $fileExt = pathinfo($storedName, PATHINFO_EXTENSION);
            $newFilename = $newName . '.' . $fileExt;

            // Update database filename
            $stmtUpdate = $conn->prepare("UPDATE files SET filename = ? WHERE id = ? AND user_id = ?");
            $stmtUpdate->bind_param("sii", $newFilename, $fileId, $userId);
            if ($stmtUpdate->execute()) {
                $message = "File renamed to '$newFilename'.";
            } else {
                $message = "Error renaming file.";
            }
            $stmtUpdate->close();
        }
        $stmtFile->close();
    }
}

?>
