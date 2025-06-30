<?php
session_start();
require_once 'dbcon.php';
session_unset();
session_destroy();
header('Location: login.php');
exit;