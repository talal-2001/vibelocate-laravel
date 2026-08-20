<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Services\Auth\JwtService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Throwable;

class VerifyEmailController extends Controller
{
    public function __construct(private JwtService $jwt)
    {
    }

    public function __invoke(Request $request)
    {
        $token = trim((string) (
            $request->isMethod('get')
                ? $request->query('token', '')
                : $request->input('token', '')
        ));

        $deviceUuid = trim((string) $request->input('device_uuid', ''));
        $deviceType = (string) $request->input('device_type', 'web');

        if ($token === '') {
            return $this->error('Verification token is required', 422);
        }

        if (!in_array($deviceType, ['ios', 'android', 'web', 'desktop'], true)) {
            return $this->error('Invalid device type', 422);
        }

        $verification = DB::table('email_verifications')
            ->where('token', $token)
            ->where('expires_at', '>', now())
            ->select('user_id')
            ->first();

        if (!$verification) {
            return $this->error('Invalid or expired verification token', 400);
        }

        $user = DB::table('users')
            ->where('id', $verification->user_id)
            ->whereNull('deleted_at')
            ->first();

        if (!$user) {
            return $this->error('User not found', 404);
        }

        DB::beginTransaction();

        try {

            // تفعيل الحساب
            DB::table('users')
                ->where('id', $verification->user_id)
                ->update([
                    'email_verified_at' => now(),
                    'status' => 'active',
                ]);

            // حذف verification token بعد استخدامه
            DB::table('email_verifications')
                ->where('user_id', $verification->user_id)
                ->delete();

            // تسجيل الجهاز
            $deviceId = null;

            if ($deviceUuid !== '') {

                $device = DB::table('devices')
                    ->where('user_id', $user->id)
                    ->where('device_uuid', $deviceUuid)
                    ->first();

                if ($device) {

                    $deviceId = (int) $device->id;

                    DB::table('devices')
                        ->where('id', $deviceId)
                        ->update([
                            'device_type' => $deviceType,
                            'updated_at' => now(),
                        ]);

                } else {

                    $deviceId = DB::table('devices')
                        ->insertGetId([
                            'user_id' => $user->id,
                            'device_uuid' => $deviceUuid,
                            'device_type' => $deviceType,
                        ]);
                }
            }

            // إنشاء Access Token
            $accessToken = $this->jwt->accessToken(
                (int) $user->id,
                $user->email
            );

            // إنشاء Refresh Token
            $refreshToken = $this->jwt->refreshToken();

            // تخزين Refresh Token
            DB::table('refresh_tokens')->insert([
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'token_hash' => hash('sha256', $refreshToken),
                'expires_at' => now()->addDays(7),
            ]);

            // تسجيل Login History
            DB::table('login_history')->insert([
                'user_id' => $user->id,
                'device_id' => $deviceId,
                'ip_address' => $request->ip() ?: '127.0.0.1',
                'login_status' => 'success',
            ]);

            DB::commit();

            return response()->json([
                'success' => true,
                'message' => 'Email verified successfully',
                'access_token' => $accessToken,
                'refresh_token' => $refreshToken,
                'token_type' => 'Bearer',
                'expires_in' => 900,
                'user' => [
                    'id' => $user->id,
                    'email' => $user->email,
                ],
            ]);

        } catch (Throwable $e) {

            DB::rollBack();

            return response()->json([
                'success' => false,
                'message' => 'Email verification failed',
                'details' => app()->environment('local')
                    ? $e->getMessage()
                    : null,
            ], 500);
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