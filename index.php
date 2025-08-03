<?php
session_start();
require_once 'dbcon.php';

// Redirect if not logged in (both user_id and email expected)
if (!isset($_SESSION['user_id'], $_SESSION['user_email'])) {
    header('Location: login.php');
    exit();
}

$message = '';

// Create new folder
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['new_folder'])) {
    $folderName = trim($_POST['new_folder']);
    $userId = $_SESSION['user_id'];

    if ($folderName !== '') {
        // Check if folder exists for this user
        $stmt = $conn->prepare("SELECT id FROM folders WHERE user_id = ? AND name = ?");
        if (!$stmt) die("Prepare failed: " . $conn->error);
        $stmt->bind_param("is", $userId, $folderName);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            $stmtInsert = $conn->prepare("INSERT INTO folders (user_id, name) VALUES (?, ?)");
            if (!$stmtInsert) die("Prepare failed: " . $conn->error);
            $stmtInsert->bind_param("is", $userId, $folderName);
            if ($stmtInsert->execute()) {
                $message = "Folder '" . htmlspecialchars($folderName) . "' created successfully.";
            } else {
                $message = "Failed to create folder.";
            }
            $stmtInsert->close();
        } else {
            $message = "Folder name must be unique.";
        }
        $stmt->close();
    } else {
        $message = "Folder name cannot be empty.";
    }
}

// Handle file upload
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['userfile'], $_POST['filename'])) {
    $uploadDir = __DIR__ . '/uploads/';
    if (!is_dir($uploadDir)) mkdir($uploadDir, 0777, true);

    $userId = $_SESSION['user_id'];
    $originalName = basename($_FILES['userfile']['name']);
    $fileType = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));
    $allowedTypes = ['txt', 'pdf', 'doc', 'docx', 'jpg', 'jpeg', 'png', 'gif'];

    $inputFileName = trim($_POST['filename']);
    // Sanitize input filename (remove extension if exists)
    $inputFileNameNoExt = preg_replace('/\.[^.]+$/', '', $inputFileName);
    $safeName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $inputFileNameNoExt);

    // Folder ID handling
    $folderId = $_POST['folder_id'] ?? null;
    if ($folderId === '' || !is_numeric($folderId)) {
        $folderId = null;
    } else {
        $folderId = (int)$folderId;
    }

    if (!in_array($fileType, $allowedTypes)) {
        $message = "Invalid file type. Allowed types: " . implode(', ', $allowedTypes);
    } elseif ($safeName === '') {
        $message = "Invalid file name.";
    } else {
        // Check if filename already exists for this user in the folder
        $stmt = $conn->prepare("SELECT id FROM files WHERE user_id = ? AND folder_id <=> ? AND filename = ?");
        if (!$stmt) die("Prepare failed: " . $conn->error);
        $filenameWithExt = $safeName . '.' . $fileType;
        $stmt->bind_param("iis", $userId, $folderId, $filenameWithExt);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            // Prepare stored name to avoid collisions: uniqid + original extension
            $storedName = uniqid() . '.' . $fileType;
            $targetFile = $uploadDir . $storedName;

            if (move_uploaded_file($_FILES['userfile']['tmp_name'], $targetFile)) {
                $stmtInsert = $conn->prepare("INSERT INTO files (user_id, folder_id, filename, stored_name, file_type) VALUES (?, ?, ?, ?, ?)");
                if (!$stmtInsert) die("Prepare failed: " . $conn->error);
                $stmtInsert->bind_param("issss", $userId, $folderId, $filenameWithExt, $storedName, $fileType);

                if ($stmtInsert->execute()) {
                    $message = "File uploaded successfully.";
                } else {
                    $message = "Failed to save file info to database.";
                    unlink($targetFile); // remove uploaded file on failure
                }
                $stmtInsert->close();
            } else {
                $message = "Error uploading file.";
            }
        } else {
            $message = "File name already exists in this folder.";
        }
        $stmt->close();
    }
}

// --- Rename Folder Handler ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rename_folder_id'], $_POST['rename_folder_name'])) {
    $renameFolderId = (int)$_POST['rename_folder_id'];
    $newFolderName = trim($_POST['rename_folder_name']);
    $userId = $_SESSION['user_id'];

    if ($newFolderName !== '') {
        // Check if new folder name already exists for this user (excluding the current folder)
        $stmt = $conn->prepare("SELECT id FROM folders WHERE user_id = ? AND name = ? AND id != ?");
        if (!$stmt) die("Prepare failed: " . $conn->error);
        $stmt->bind_param("isi", $userId, $newFolderName, $renameFolderId);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows === 0) {
            $stmtUpdate = $conn->prepare("UPDATE folders SET name = ? WHERE id = ? AND user_id = ?");
            if (!$stmtUpdate) die("Prepare failed: " . $conn->error);
            $stmtUpdate->bind_param("sii", $newFolderName, $renameFolderId, $userId);
            if ($stmtUpdate->execute()) {
                $message = "Folder renamed successfully.";
            } else {
                $message = "Failed to rename folder.";
            }
            $stmtUpdate->close();
        } else {
            $message = "Folder name already exists.";
        }
        $stmt->close();
    } else {
        $message = "New folder name cannot be empty.";
    }
}

// --- Delete Folder Handler ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_folder_id'])) {
    $deleteFolderId = (int)$_POST['delete_folder_id'];
    $userId = $_SESSION['user_id'];

    // First check if folder is empty
    $stmtCheck = $conn->prepare("SELECT COUNT(*) FROM files WHERE folder_id = ? AND user_id = ?");
    if (!$stmtCheck) die("Prepare failed: " . $conn->error);
    $stmtCheck->bind_param("ii", $deleteFolderId, $userId);
    $stmtCheck->execute();
    $stmtCheck->bind_result($fileCount);
    $stmtCheck->fetch();
    $stmtCheck->close();

    if ($fileCount == 0) {
        $stmtDelete = $conn->prepare("DELETE FROM folders WHERE id = ? AND user_id = ?");
        if (!$stmtDelete) die("Prepare failed: " . $conn->error);
        $stmtDelete->bind_param("ii", $deleteFolderId, $userId);
        if ($stmtDelete->execute()) {
            $message = "Folder deleted successfully.";
            // If we're currently viewing this folder, redirect to root
            if (isset($_GET['folder_id']) && (int)$_GET['folder_id'] === $deleteFolderId) {
                header("Location: index.php");
                exit();
            }
        } else {
            $message = "Failed to delete folder.";
        }
        $stmtDelete->close();
    } else {
        $message = "Cannot delete folder - it contains files.";
    }
}

// --- Rename File Handler ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['rename_file_id'], $_POST['rename_file_name'])) {
    $renameFileId = (int)$_POST['rename_file_id'];
    $newFileNameRaw = trim($_POST['rename_file_name']);
    $userId = $_SESSION['user_id'];

    // Sanitize new file name
    $safeNewName = preg_replace('/[^a-zA-Z0-9_\-]/', '_', $newFileNameRaw);
    if ($safeNewName === '') {
        $message = "Invalid new file name.";
    } else {
        // Get current file info to get file extension and folder_id
        $stmt = $conn->prepare("SELECT filename, folder_id FROM files WHERE id = ? AND user_id = ?");
        if (!$stmt) die("Prepare failed: " . $conn->error);
        $stmt->bind_param("ii", $renameFileId, $userId);
        $stmt->execute();
        $stmt->bind_result($currentFilename, $currentFolderId);
        if ($stmt->fetch()) {
            $stmt->close();

            $ext = strtolower(pathinfo($currentFilename, PATHINFO_EXTENSION));
            $newFilenameWithExt = $safeNewName . '.' . $ext;

            // Check if file with new name already exists in the same folder for this user
            $stmtCheck = $conn->prepare("SELECT id FROM files WHERE user_id = ? AND folder_id <=> ? AND filename = ? AND id != ?");
            if (!$stmtCheck) die("Prepare failed: " . $conn->error);
            $stmtCheck->bind_param("iisi", $userId, $currentFolderId, $newFilenameWithExt, $renameFileId);
            $stmtCheck->execute();
            $stmtCheck->store_result();

            if ($stmtCheck->num_rows === 0) {
                $stmtCheck->close();

                // Update filename in database
                $stmtUpdate = $conn->prepare("UPDATE files SET filename = ? WHERE id = ? AND user_id = ?");
                if (!$stmtUpdate) die("Prepare failed: " . $conn->error);
                $stmtUpdate->bind_param("sii", $newFilenameWithExt, $renameFileId, $userId);

                if ($stmtUpdate->execute()) {
                    $message = "File renamed successfully.";
                } else {
                    $message = "Failed to rename file.";
                }
                $stmtUpdate->close();
            } else {
                $message = "File name already exists in this folder.";
                $stmtCheck->close();
            }
        } else {
            $stmt->close();
            $message = "File not found.";
        }
    }
}

// --- Delete File Handler ---
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['delete_file_id'])) {
    $deleteFileId = (int)$_POST['delete_file_id'];
    $userId = $_SESSION['user_id'];

    // Get file info to delete from filesystem
    $stmt = $conn->prepare("SELECT stored_name FROM files WHERE id = ? AND user_id = ?");
    if (!$stmt) die("Prepare failed: " . $conn->error);
    $stmt->bind_param("ii", $deleteFileId, $userId);
    $stmt->execute();
    $stmt->bind_result($storedName);
    if ($stmt->fetch()) {
        $stmt->close();

        // Delete from database
        $stmtDelete = $conn->prepare("DELETE FROM files WHERE id = ? AND user_id = ?");
        if (!$stmtDelete) die("Prepare failed: " . $conn->error);
        $stmtDelete->bind_param("ii", $deleteFileId, $userId);
        
        if ($stmtDelete->execute()) {
            // Delete from filesystem
            $filePath = __DIR__ . '/uploads/' . $storedName;
            if (file_exists($filePath)) {
                unlink($filePath);
            }
            $message = "File deleted successfully.";
        } else {
            $message = "Failed to delete file.";
        }
        $stmtDelete->close();
    } else {
        $stmt->close();
        $message = "File not found.";
    }
}

// --- Folder navigation part ---
// Get folder_id from GET param or default to NULL (root folder)
$folderId = isset($_GET['folder_id']) && is_numeric($_GET['folder_id']) ? (int)$_GET['folder_id'] : null;

// Fetch all user folders for sidebar
$folderStmt = $conn->prepare("SELECT id, name FROM folders WHERE user_id = ?");
if (!$folderStmt) die("Prepare failed: " . $conn->error);
$folderStmt->bind_param("i", $_SESSION['user_id']);
$folderStmt->execute();
$foldersResult = $folderStmt->get_result();

// Fetch files inside the selected folder (or root)
$fileStmt = $conn->prepare("SELECT * FROM files WHERE user_id = ? AND (folder_id <=> ?) ORDER BY uploaded_at DESC");
if (!$fileStmt) die("Prepare failed: " . $conn->error);
$fileStmt->bind_param("ii", $_SESSION['user_id'], $folderId);
$fileStmt->execute();
$files = $fileStmt->get_result();

// Get folder name for current folder if not root
$currentFolderName = 'Default Folder';
if ($folderId !== null) {
    $stmt = $conn->prepare("SELECT name FROM folders WHERE id = ? AND user_id = ?");
    if ($stmt) {
        $stmt->bind_param("ii", $folderId, $_SESSION['user_id']);
        $stmt->execute();
        $stmt->bind_result($fname);
        if ($stmt->fetch()) {
            $currentFolderName = $fname;
        }
        $stmt->close();
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>File Storage App</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background: #87CEEB; /* Sky blue background */
        }
        .logout-link {
            text-align: right;
            margin-bottom: 10px;
        }
        .logout-link a {
            color: #3498db;
            text-decoration: none;
            font-weight: bold;
        }
        .container {
            display: flex;
            max-width: 1000px;
            margin: auto;
            border: 1px solid #ddd;
            background: white;
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 4px 12px rgba(0,0,0,0.1);
        }
        .folders {
            width: 250px;
            background: #fafafa;
            border-right: 1px solid #ddd;
            padding: 15px;
        }
        .folders h3 {
            margin-top: 0;
            margin-bottom: 15px;
            font-weight: 600;
            color: #333;
            text-align: center;
            border-bottom: 1px solid #ddd;
            padding-bottom: 10px;
        }
        .folder-list {
            list-style: none;
            padding: 0;
            margin: 0;
        }
        .folder-list li {
            margin-bottom: 8px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }
        .folder-list a {
            text-decoration: none;
            color: #555;
            display: block;
            padding: 6px 10px;
            border-radius: 4px;
            transition: background-color 0.2s;
            flex-grow: 1;
        }
        .folder-list a.active, .folder-list a:hover {
            background-color: #3498db;
            color: white;
        }
        .main-content {
            flex: 1;
            padding: 20px;
        }
        h2, h3 {
            color: #222;
        }
        form {
            margin-bottom: 25px;
            background: #f9f9f9;
            padding: 12px 15px;
            border-radius: 6px;
            border: 1px solid #ccc;
        }
        .form-group {
            margin-bottom: 12px;
        }
        label {
            display: block;
            margin-bottom: 6px;
            font-weight: 600;
            color: #444;
        }
        input[type="text"], select, input[type="file"] {
            width: 100%;
            padding: 7px 10px;
            box-sizing: border-box;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }
        input[type="submit"] {
            background-color: #3498db;
            color: white;
            border: none;
            padding: 9px 15px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
            font-size: 15px;
            transition: background-color 0.3s ease;
        }
        input[type="submit"]:hover {
            background-color: #2980b9;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background: white;
        }
        table th, table td {
            text-align: left;
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
            font-size: 14px;
            color: #333;
        }
        table th {
            background: #f0f2f5;
            font-weight: 700;
        }
        .message {
            margin-bottom: 15px;
            padding: 10px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 15px;
        }
        .success {
            background-color: #d4edda;
            color: #155724;
        }
        .error {
            background-color: #f8d7da;
            color: #721c24;
        }
        
        /* Dropdown menu styles */
        .dropdown {
            position: relative;
            display: inline-block;
        }
        .dropdown-toggle {
            cursor: pointer;
            padding: 5px 10px;
            border-radius: 4px;
        }
        .dropdown-toggle:hover {
            background-color: #eee;
        }
        .dropdown-menu {
            display: none;
            position: absolute;
            right: 0;
            background-color: white;
            min-width: 160px;
            box-shadow: 0px 8px 16px 0px rgba(0,0,0,0.2);
            z-index: 1;
            border-radius: 4px;
            overflow: hidden;
        }
        .dropdown-menu a {
            color: #333;
            padding: 8px 12px;
            text-decoration: none;
            display: block;
            font-size: 14px;
        }
        .dropdown-menu a:hover {
            background-color: #f1f1f1;
        }
        .dropdown:hover .dropdown-menu {
            display: block;
        }
        
        /* Action buttons */
        .action-btn {
            background: none;
            border: none;
            color: #666;
            cursor: pointer;
            padding: 5px;
            font-size: 18px;
        }
        .action-btn:hover {
            color: #3498db;
        }
        
        /* Modal styles */
        .modal {
            display: none;
            position: fixed;
            z-index: 100;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            overflow: auto;
            background-color: rgba(0,0,0,0.4);
        }
        .modal-content {
            background-color: #fefefe;
            margin: 15% auto;
            padding: 20px;
            border: 1px solid #888;
            width: 80%;
            max-width: 500px;
            border-radius: 8px;
        }
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        .close:hover {
            color: black;
        }
        .modal-footer {
            margin-top: 20px;
            text-align: right;
        }
        .modal-footer button {
            padding: 8px 16px;
            margin-left: 10px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
        }
        .btn-cancel {
            background-color: #f1f1f1;
        }
        .btn-danger {
            background-color: #dc3545;
            color: white;
        }
    </style>

</head>
<body>

<div class="logout-link">
    <a href="logout.php">Logout</a>
</div>

<div class="container">

    <div class="folders">
        <h3>Folders</h3>
        <ul class="folder-list">
            <li>
                <a href="index.php" class="<?= $folderId === null ? 'active' : '' ?>">Default Folder</a>
            </li>
            <?php while ($folder = $foldersResult->fetch_assoc()): ?>
                <li>
                    <a href="?folder_id=<?= (int)$folder['id'] ?>" class="<?= ($folderId === (int)$folder['id']) ? 'active' : '' ?>">
                        <?= htmlspecialchars($folder['name']) ?>
                    </a>
                    <div class="dropdown">
                        <button class="action-btn dropdown-toggle">⋮</button>
                        <div class="dropdown-menu">
                            <a href="#" onclick="showRenameFolderModal(<?= (int)$folder['id'] ?>, '<?= htmlspecialchars(addslashes($folder['name'])) ?>')">Rename</a>
                            <a href="#" onclick="showDeleteFolderModal(<?= (int)$folder['id'] ?>, '<?= htmlspecialchars(addslashes($folder['name'])) ?>')">Delete</a>
                        </div>
                    </div>
                </li>
            <?php endwhile; ?>
        </ul>

        <h3>Create Folder</h3>
        <form method="post" autocomplete="off">
            <div class="form-group">
                <label for="new_folder">Folder Name:</label>
                <input type="text" name="new_folder" id="new_folder" required>
            </div>
            <input type="submit" value="Create Folder">
        </form>
    </div>

    <div class="main-content">
        <h2>Files in '<?= htmlspecialchars($currentFolderName) ?>'</h2>

        <?php if ($message): ?>
            <div class="message <?= strpos($message, 'successfully') !== false ? 'success' : 'error' ?>">
                <?= htmlspecialchars($message) ?>
            </div>
        <?php endif; ?>

        <h3>Upload File</h3>
        <form method="post" enctype="multipart/form-data" autocomplete="off">
            <div class="form-group">
                <label for="filename">File Name (without extension):</label>
                <input type="text" name="filename" id="filename" required>
            </div>
            <div class="form-group">
                <label for="userfile">Select File:</label>
                <input type="file" name="userfile" id="userfile" required>
            </div>
            <div class="form-group">
                <label for="folder_id">Upload to Folder:</label>
                <select name="folder_id" id="folder_id">
                    <option value="">Default Folder</option>
                    <?php
                    // Reset folders pointer again
                    $foldersResult->data_seek(0);
                    while ($folder = $foldersResult->fetch_assoc()):
                    ?>
                        <option value="<?= (int)$folder['id'] ?>" <?= ($folderId === (int)$folder['id']) ? 'selected' : '' ?>>
                            <?= htmlspecialchars($folder['name']) ?>
                        </option>
                    <?php endwhile; ?>
                </select>
            </div>
            <input type="submit" value="Upload File">
        </form>

        <h3>Files List</h3>
        <table>
            <thead>
            <tr>
                <th>Filename</th>
                <th>File Type</th>
                <th>Uploaded At</th>
                <th>Actions</th>
            </tr>
            </thead>
            <tbody>
            <?php if ($files->num_rows > 0): ?>
                <?php
                $files->data_seek(0);
                while ($file = $files->fetch_assoc()):
                    $downloadUrl = 'download.php?file=' . urlencode($file['stored_name']);
                ?>
                    <tr>
                        <td><?= htmlspecialchars($file['filename']) ?></td>
                        <td><?= htmlspecialchars(strtoupper($file['file_type'])) ?></td>
                        <td><?= htmlspecialchars($file['uploaded_at']) ?></td>
                        <td>
                            <a href="<?= $downloadUrl ?>" target="_blank" rel="noopener noreferrer">Download</a> | 
                            <div class="dropdown" style="display: inline-block;">
                                <button class="action-btn dropdown-toggle">⋮</button>
                                <div class="dropdown-menu">
                                    <a href="#" onclick="showRenameFileModal(<?= (int)$file['id'] ?>, '<?= htmlspecialchars(addslashes(pathinfo($file['filename'], PATHINFO_FILENAME))) ?>')">Rename</a>
                                    <a href="#" onclick="showDeleteFileModal(<?= (int)$file['id'] ?>, '<?= htmlspecialchars(addslashes($file['filename'])) ?>')">Delete</a>
                                </div>
                            </div>
                        </td>
                    </tr>
                <?php endwhile; ?>
            <?php else: ?>
                <tr><td colspan="4" style="text-align:center;">No files found in this folder.</td></tr>
            <?php endif; ?>
            </tbody>
        </table>
    </div>

</div>

<!-- Rename Folder Modal -->
<div id="renameFolderModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('renameFolderModal')">&times;</span>
        <h3>Rename Folder</h3>
        <form id="renameFolderForm" method="post">
            <input type="hidden" name="rename_folder_id" id="modal_rename_folder_id">
            <div class="form-group">
                <label for="modal_rename_folder_name">New Folder Name:</label>
                <input type="text" name="rename_folder_name" id="modal_rename_folder_name" required>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeModal('renameFolderModal')">Cancel</button>
                <input type="submit" value="Rename Folder">
            </div>
        </form>
    </div>
</div>

<!-- Delete Folder Modal -->
<div id="deleteFolderModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('deleteFolderModal')">&times;</span>
        <h3>Delete Folder</h3>
        <p>Are you sure you want to delete folder "<span id="deleteFolderName"></span>"?</p>
        <form id="deleteFolderForm" method="post">
            <input type="hidden" name="delete_folder_id" id="modal_delete_folder_id">
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeModal('deleteFolderModal')">Cancel</button>
                <button type="submit" class="btn-danger">Delete</button>
            </div>
        </form>
    </div>
</div>

<!-- Rename File Modal -->
<div id="renameFileModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('renameFileModal')">&times;</span>
        <h3>Rename File</h3>
        <form id="renameFileForm" method="post">
            <input type="hidden" name="rename_file_id" id="modal_rename_file_id">
            <div class="form-group">
                <label for="modal_rename_file_name">New File Name (without extension):</label>
                <input type="text" name="rename_file_name" id="modal_rename_file_name" required>
            </div>
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeModal('renameFileModal')">Cancel</button>
                <input type="submit" value="Rename File">
            </div>
        </form>
    </div>
</div>

<!-- Delete File Modal -->
<div id="deleteFileModal" class="modal">
    <div class="modal-content">
        <span class="close" onclick="closeModal('deleteFileModal')">&times;</span>
        <h3>Delete File</h3>
        <p>Are you sure you want to delete file "<span id="deleteFileName"></span>"?</p>
        <form id="deleteFileForm" method="post">
            <input type="hidden" name="delete_file_id" id="modal_delete_file_id">
            <div class="modal-footer">
                <button type="button" class="btn-cancel" onclick="closeModal('deleteFileModal')">Cancel</button>
                <button type="submit" class="btn-danger">Delete</button>
            </div>
        </form>
    </div>
</div>

<script>
    // Modal functions
    function showRenameFolderModal(folderId, currentName) {
        document.getElementById('modal_rename_folder_id').value = folderId;
        document.getElementById('modal_rename_folder_name').value = currentName;
        document.getElementById('renameFolderModal').style.display = 'block';
    }

    function showDeleteFolderModal(folderId, folderName) {
        document.getElementById('modal_delete_folder_id').value = folderId;
        document.getElementById('deleteFolderName').textContent = folderName;
        document.getElementById('deleteFolderModal').style.display = 'block';
    }

    function showRenameFileModal(fileId, currentName) {
        document.getElementById('modal_rename_file_id').value = fileId;
        document.getElementById('modal_rename_file_name').value = currentName;
        document.getElementById('renameFileModal').style.display = 'block';
    }

    function showDeleteFileModal(fileId, fileName) {
        document.getElementById('modal_delete_file_id').value = fileId;
        document.getElementById('deleteFileName').textContent = fileName;
        document.getElementById('deleteFileModal').style.display = 'block';
    }

    function closeModal(modalId) {
        document.getElementById(modalId).style.display = 'none';
    }

    // Close modal when clicking outside of it
    window.onclick = function(event) {
        if (event.target.className === 'modal') {
            event.target.style.display = 'none';
        }
    }
</script>

</body>
</html>
