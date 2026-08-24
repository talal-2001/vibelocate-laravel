<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;
use Throwable;

class ResetPasswordController extends Controller
{
    public function __invoke(Request $request)
    {
        $email = strtolower(
            trim((string) $request->input('email', ''))
        );

        $otp = trim((string) (
            $request->input('otp')
            ?? $request->input('code')
            ?? $request->input('token')
            ?? ''
        ));

        $newPassword = (string) $request->input(
            'new_password',
            ''
        );

        /*
        |--------------------------------------------------------------------------
        | Validation
        |--------------------------------------------------------------------------
        */

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return $this->error(
                'Invalid email address',
                422
            );
        }

        if ($otp === '') {
            return $this->error(
                'Verification code is required',
                422
            );
        }

        if (
            strlen($otp) !== 6 ||
            !ctype_digit($otp)
        ) {
            return $this->error(
                'Verification code must be 6 digits',
                422
            );
        }

        if (strlen($newPassword) < 8) {
            return $this->error(
                'Password must be at least 8 characters',
                422
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Find OTP
        |--------------------------------------------------------------------------
        */

        $record = DB::table('password_resets')
            ->where('email', $email)
            ->where('token', $otp)
            ->where('expires_at', '>', now())
            ->first();

        if (!$record) {
            return $this->error(
                'Invalid or expired verification code',
                400
            );
        }

        /*
        |--------------------------------------------------------------------------
        | Find User
        |--------------------------------------------------------------------------
        */

        $user = DB::table('users')
            ->where('email', $email)
            ->whereNull('deleted_at')
            ->select(
                'id',
                'password_hash'
            )
            ->first();

        if (!$user) {
            return $this->error(
                'User not found',
                404
            );
        }

        if (
            Hash::check(
                $newPassword,
                $user->password_hash
            )
        ) {
            return $this->error(
                'New password must be different from your current password',
                422
            );
        }

        DB::beginTransaction();

        try {

            /*
            |--------------------------------------------------------------------------
            | Change Password
            |--------------------------------------------------------------------------
            */

            DB::table('users')
                ->where('id', $user->id)
                ->update([
                    'password_hash' =>
                        Hash::make($newPassword),
                ]);

            /*
            |--------------------------------------------------------------------------
            | Remove Used OTP
            |--------------------------------------------------------------------------
            */

            DB::table('password_resets')
                ->where('email', $email)
                ->delete();

            /*
            |--------------------------------------------------------------------------
            | Revoke Sessions
            |--------------------------------------------------------------------------
            */

            DB::table('refresh_tokens')
                ->where('user_id', $user->id)
                ->update([
                    'is_revoked' => 1,
                ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' =>
                    'Password reset successfully. Please log in with your new password.',
            ], 200);

        } catch (Throwable $e) {

            if (DB::transactionLevel() > 0) {
                DB::rollBack();
            }

            report($e);

            return $this->error(
                'Password reset failed',
                500
            );
        }
    }

    private function error(
        string $message,
        int $status
    ) {
        return response()->json([
            'success' => false,
            'message' => $message,
        ], $status);
    }
}