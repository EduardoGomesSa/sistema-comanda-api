<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\UserController;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Route;

Route::post('/register', [AuthController::class, 'register']);
Route::post('/login', [AuthController::class, 'login']);

Route::middleware(['auth:sanctum'])->group(function () {
    Route::post('/validate-token', [AuthController::class, 'validateToken']);

    Route::post('/users', [UserController::class, 'store']);
    Route::delete('/users', [UserController::class, 'destroy']);
});
