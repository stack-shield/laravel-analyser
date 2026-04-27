<?php

use Illuminate\Support\Facades\Route;

// Auth route without throttle
Route::post('/login', [App\Http\Controllers\AuthController::class, 'login']);

// Route with user-scoped model binding but no auth
Route::get('/users/{user}/orders', [App\Http\Controllers\OrderController::class, 'index']);

// Safe: has auth middleware
Route::get('/profile/{user}', [App\Http\Controllers\ProfileController::class, 'show'])
    ->middleware('auth');
