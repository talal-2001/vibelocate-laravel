<?php

namespace App\Http\Controllers\Api;

use App\Services\Auth\JwtService;
use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Throwable;

class RegisterController extends Controller
{
    public function __construct(private JwtService $jwt) {}

    public function __invoke(Request $request)
    {
        $firstName = trim((string) $request->input('first_name', ''));
        $lastName = trim((string) $request->input('last_name', ''));
        $email = strtolower(trim((string) $request->input('email', '')));
        $phone = trim((string) $request->input('phone', ''));
        $password = (string) $request->input('password', '');
        $roleSlug = (string) $request->input('role_slug', 'tenant');

        if ($firstName === '' || $lastName === '') {
            return $this->error(
                'First name and last name are required',
                422
            );
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->error(
                'Invalid email address',
                422
            );
        }

        if (strlen($password) < 8) {
            return $this->error(
                'Password must be at least 8 characters',
                422
            );
        }

        if (!in_array($roleSlug, ['tenant', 'owner'], true)) {
            return $this->error(
                'Invalid registration role',
                422
            );
        }

        try {
            if (
                DB::table('users')
                    ->where('email', $email)
                    ->exists()
            ) {
                return $this->error(
                    'Email already registered',
                    409
                );
            }

            if (
                $phone !== '' &&
                DB::table('users')
                    ->where('phone', $phone)
                    ->exists()
            ) {
                return $this->error(
                    'Phone already registered',
                    409
                );
            }

            DB::beginTransaction();

            $userId = DB::table('users')->insertGetId([
                'first_name' => $firstName,
                'last_name' => $lastName,
                'email' => $email,
                'phone' => $phone !== '' ? $phone : null,
                'password_hash' => Hash::make($password),
                'status' => 'pending',
            ]);

            $role = DB::table('roles')
                ->where('slug', $roleSlug)
                ->first();

            if (!$role) {
                throw new \RuntimeException('Role not found');
            }

            DB::table('user_roles')->insert([
                'user_id' => $userId,
                'role_id' => $role->id,
            ]);

            DB::table('user_profiles')->insert([
                'user_id' => $userId,
                'preferred_language' => 'en',
                'currency' => 'AED',
            ]);

            $verificationToken = $this->jwt->emailToken();

            DB::table('email_verifications')->insert([
                'user_id' => $userId,
                'token' => $verificationToken,
                'expires_at' => now()->addDay(),
            ]);

            $referralCode = strtoupper(
                'VIBE-' .
                $userId .
                '-' .
                bin2hex(random_bytes(3))
            );

            DB::table('referral_codes')->insert([
                'user_id' => $userId,
                'code' => $referralCode,
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Registration successful. Please verify your email.',
                'user_id' => $userId,
                'verification_token' => $verificationToken,
            ], 201, [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

        } catch (Throwable $e) {

            if (DB::transactionLevel() > 0) {
                DB::rollBack();
            }

            report($e);

            /*
             * TEMPORARY DEBUG RESPONSE
             * سنرجع نحذف تفاصيل الخطأ بعد حل المشكلة.
             */
            return response()->json([
                'success' => false,
                'message' => 'Registration failed',
                'error' => $e->getMessage(),
                'exception' => get_class($e),
                'file' => $e->getFile(),
                'line' => $e->getLine(),
            ], 500, [], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        }
    }

    private function error(string $message, int $status)
    {
        return response()->json([
            'success' => false,
            'message' => $message,
        ], $status);
    }
}