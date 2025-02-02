<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;

/**
 * @OA\Info(
 *     title="YouTube Video Downloader API",
 *     version="1.0",
 *     description="API for downloading YouTube videos"
 * )
 *
 * @OA\Tag(
 *     name="YouTube",
 *     description="YouTube Video Download Endpoints"
 * )
 */
class YoutubeDownloadController extends Controller
{
    /**
     * @OA\Get(
     *     path="/api/download",
     *     tags={"YouTube"},
     *     summary="Download a YouTube video",
     *     description="Downloads a YouTube video and returns the file.",
     *     @OA\Parameter(
     *         name="url",
     *         in="query",
     *         required=true,
     *         description="YouTube video URL",
     *         @OA\Schema(type="string", example="https://www.youtube.com/watch?v=dQw4w9WgXcQ")
     *     ),
     *     @OA\Response(
     *         response=200,
     *         description="Video downloaded successfully",
     *         @OA\MediaType(
     *             mediaType="application/octet-stream",
     *             @OA\Schema(type="string", format="binary")
     *         )
     *     ),
     *     @OA\Response(
     *         response=400,
     *         description="Invalid input"
     *     ),
     *     @OA\Response(
     *         response=500,
     *         description="Failed to download video"
     *     )
     * )
     */
    public function download(Request $request)
    {
        $request->validate([
            'url' => 'required|url'
        ]);

        $videoUrl = $request->input('url');

        // Generate a unique filename
        $filename = uniqid() . ".mp4";
        $outputPath = storage_path("app/public/$filename");

        // Run yt-dlp command
        $process = new Process([
            'yt-dlp',
            '-f', 'best',
            '-o', $outputPath,
            $videoUrl
        ]);

        $process->run();

        if (!$process->isSuccessful()) {
            return response()->json(['error' => 'Failed to download video'], 500);
        }

        return response()->download($outputPath)->deleteFileAfterSend(true);
    }
}
