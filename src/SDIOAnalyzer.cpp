// The MIT License (MIT)
//
// Copyright (c) 2013 Erick Fuentes http://erickfuent.es
// Copyright (c) 2014 Kuy Mainwaring http://logiblock.com
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include <algorithm>
#include <cstdio>
#include <memory>
#include <string>

#include <AnalyzerChannelData.h>
#include <AnalyzerResults.h>

#include "SDIOAnalyzer.h"
#include "SDIOAnalyzerSettings.h"

namespace
{
    const char* R1StateText( U32 state )
    {
        switch( state )
        {
        case 0:
            return "IDLE";
        case 1:
            return "READY";
        case 2:
            return "IDENT";
        case 3:
            return "STBY";
        case 4:
            return "TRAN";
        case 5:
            return "DATA";
        case 6:
            return "RCV";
        case 7:
            return "PRG";
        case 8:
            return "DIS";
        default:
            return "RFU";
        }
    }

    std::string BuildR1String( U32 status )
    {
        char buf[ 128 ];
        const U32 state = ( status >> 9 ) & 0xF;
        const U32 ready = ( status >> 8 ) & 0x1;
        std::snprintf( buf, sizeof( buf ), "STATUS=0x%08X | STATE=%s | READY=%u", status, R1StateText( state ), ready );
        return std::string( buf );
    }

    std::string BuildParsingString( U32 cmd, U32 arg, bool is_cmd_packet )
    {
        char buf[ 128 ];

        if( cmd == 0 )
        {
            if( is_cmd_packet )
                return std::string( "GO_IDLE" );
            return std::string();
        }
        else if( cmd == 3 )
        {
            if( is_cmd_packet )
            {
                const U32 rca = ( arg >> 16 ) & 0xFFFF;
                std::snprintf( buf, sizeof( buf ), "RCA=0x%04X", rca );
                return std::string( buf );
            }
            else
            {
                const U32 rca = ( arg >> 16 ) & 0xFFFF;
                const U32 status = arg & 0xFFFF;
                std::snprintf( buf, sizeof( buf ), "RCA=0x%04X | STATUS=0x%04X", rca, status );
                return std::string( buf );
            }
        }
        else if( cmd == 5 )
        {
            if( is_cmd_packet )
            {
                const U32 ocr = arg & 0xFFFFFF;
                const U32 s18 = ( arg >> 24 ) & 0x1;
                std::snprintf( buf, sizeof( buf ), "OCR=0x%06X | S18=%u", ocr, s18 );
                return std::string( buf );
            }
            else
            {
                const U32 ready = ( arg >> 31 ) & 0x1;
                const U32 num_io = ( arg >> 28 ) & 0x7;
                const U32 mem = ( arg >> 27 ) & 0x1;
                const U32 ocr = arg & 0xFFFFFF;
                std::snprintf( buf, sizeof( buf ), "READY=%u | NUM_IO=%u | MEM_PRESENT=%u | OCR=0x%06X", ready, num_io, mem, ocr );
                return std::string( buf );
            }
        }
        else if( cmd == 7 )
        {
            if( is_cmd_packet )
            {
                const U32 rca = ( arg >> 16 ) & 0xFFFF;
                if( rca == 0 )
                    return std::string( "DESELECT RCA=0x0000" );
                std::snprintf( buf, sizeof( buf ), "SELECT RCA=0x%04X", rca );
                return std::string( buf );
            }
            return BuildR1String( arg );
        }
        else if( cmd == 8 )
        {
            const U32 vhs = ( arg >> 8 ) & 0xF;
            const U32 check = arg & 0xFF;
            std::snprintf( buf, sizeof( buf ), "VHS=0x%X | CHECK=0x%02X", vhs, check );
            return std::string( buf );
        }
        else if( cmd == 11 )
        {
            if( is_cmd_packet )
                return std::string( "VOLTAGE_SWITCH" );
            return BuildR1String( arg );
        }
        else if( cmd == 12 )
        {
            if( is_cmd_packet )
                return std::string( "STOP_TRANSMISSION" );
            return BuildR1String( arg );
        }
        else if( cmd == 13 )
        {
            if( is_cmd_packet )
            {
                const U32 rca = ( arg >> 16 ) & 0xFFFF;
                std::snprintf( buf, sizeof( buf ), "RCA=0x%04X", rca );
                return std::string( buf );
            }
            return BuildR1String( arg );
        }
        else if( cmd == 16 )
        {
            if( is_cmd_packet )
            {
                std::snprintf( buf, sizeof( buf ), "BLOCKLEN=%u", arg );
                return std::string( buf );
            }
            return BuildR1String( arg );
        }
        else if( cmd == 59 )
        {
            if( is_cmd_packet )
            {
                const U32 on = arg & 0x1;
                std::snprintf( buf, sizeof( buf ), "CRC_ON=%u", on );
                return std::string( buf );
            }
            return BuildR1String( arg );
        }

        if( cmd == 52 )
        {
            if( is_cmd_packet )
            {
                const bool write = ( ( arg >> 31 ) & 0x1 ) != 0;
                const U32 func = ( arg >> 28 ) & 0x7;
                const U32 raw = ( arg >> 27 ) & 0x1;
                const U32 addr = ( arg >> 9 ) & 0x1FFFF;
                const U32 data = arg & 0xFF;
                std::snprintf( buf, sizeof( buf ), "%s | FUNC=%u | RAW=%u | ADDR=0x%X | DATA=0x%02X", write ? "WRITE" : "READ", func, raw,
                               addr, data );
                return std::string( buf );
            }
            else
            {
                const U32 v = arg & 0xFFFF;
                const U32 state = ( v >> 12 ) & 0x3;
                const U32 fn = ( v >> 8 ) & 0x7;
                const U32 data = v & 0xFF;
                const bool crc = ( v & ( 1u << 15 ) ) != 0;
                const bool ill = ( v & ( 1u << 14 ) ) != 0;
                const bool err = ( v & ( 1u << 11 ) ) != 0;
                const bool oor = ( v & ( 1u << 7 ) ) != 0;

                const char* state_txt[] = { "DIS", "CMD", "TRN", "RFU" };
                std::string flags;
                if( crc )
                    flags += "COM_CRC_ERROR";
                if( ill )
                    flags += flags.empty() ? "ILLEGAL_COMMAND" : ", ILLEGAL_COMMAND";
                if( err )
                    flags += flags.empty() ? "ERROR" : ", ERROR";
                if( oor )
                    flags += flags.empty() ? "OUT_OF_RANGE" : ", OUT_OF_RANGE";

                std::snprintf( buf, sizeof( buf ), "STATE=%s | FN=%u | DATA=0x%02X", state_txt[ state ], fn, data );
                std::string out = buf;
                if( !flags.empty() )
                    out += " | FLAGS: " + flags;
                return out;
            }
        }
        else if( cmd == 53 )
        {
            if( is_cmd_packet )
            {
                const bool write = ( ( arg >> 31 ) & 0x1 ) != 0;
                const U32 func = ( arg >> 28 ) & 0x7;
                const U32 raw = ( arg >> 26 ) & 0x1; // op-code, labeled RAW per request
                const U32 addr = ( arg >> 9 ) & 0x1FFFF;
                const U32 count = arg & 0x1FF;
                std::snprintf( buf, sizeof( buf ), "%s | FN=%u | RAW=%u | ADDR=0x%X | DATA=0x%X", write ? "WRITE" : "READ", func, raw, addr,
                               count );
                return std::string( buf );
            }
            else
            {
                const U32 v = arg & 0xFFFF;
                const U32 state = ( v >> 12 ) & 0x3;
                const U32 fn = ( v >> 8 ) & 0x7;
                const U32 data = v & 0xFF;
                const bool crc = ( v & ( 1u << 15 ) ) != 0;
                const bool ill = ( v & ( 1u << 14 ) ) != 0;
                const bool err = ( v & ( 1u << 11 ) ) != 0;
                const bool oor = ( v & ( 1u << 7 ) ) != 0;

                const char* state_txt[] = { "DIS", "CMD", "TRN", "RFU" };
                std::string flags;
                if( crc )
                    flags += "COM_CRC_ERROR";
                if( ill )
                    flags += flags.empty() ? "ILLEGAL_COMMAND" : ", ILLEGAL_COMMAND";
                if( err )
                    flags += flags.empty() ? "ERROR" : ", ERROR";
                if( oor )
                    flags += flags.empty() ? "OUT_OF_RANGE" : ", OUT_OF_RANGE";

                std::snprintf( buf, sizeof( buf ), "STATE=%s | FN=%u | DATA=0x%02X", state_txt[ state ], fn, data );
                std::string out = buf;
                if( !flags.empty() )
                    out += " | FLAGS: " + flags;
                return out;
            }
        }

        return std::string();
    }
} // namespace

U32 sdCRC7( U32 crc, U8 messageByte )
{
    for( int ibit = 0; ibit < 8; ibit++ )
    {
        crc <<= 1;
        if( ( messageByte ^ crc ) & 0x80 )
            crc ^= 0x09;
        messageByte <<= 1;
    }
    return ( crc & 0x7F );
}

SDIOAnalyzer::SDIOAnalyzer()
    : Analyzer2(),
      mSettings( new SDIOAnalyzerSettings() ),
      mSimulationInitialized( false ),
      mAlreadyRun( false ),
      packetState( WAITING_FOR_PACKET ),
      frameState( TRANSMISSION_BIT ),
      frameV2( std::unique_ptr<FrameV2>( new FrameV2 ) )
{
    SetAnalyzerSettings( mSettings.get() );
    UseFrameV2();
}

SDIOAnalyzer::~SDIOAnalyzer()
{
    KillThread();
}

void SDIOAnalyzer::SetupResults()
{
    mResults.reset( new SDIOAnalyzerResults( this, mSettings.get() ) );
    SetAnalyzerResults( mResults.get() );

    // mResults->AddChannelBubblesWillAppearOn(mSettings->mClockChannel);
    mResults->AddChannelBubblesWillAppearOn( mSettings->mCmdChannel );
    if( mSettings->mDAT0Channel != UNDEFINED_CHANNEL )
        mResults->AddChannelBubblesWillAppearOn( mSettings->mDAT0Channel );
}

void SDIOAnalyzer::WorkerThread()
{
    mAlreadyRun = true;

    mClock = GetAnalyzerChannelData( mSettings->mClockChannel );
    mCmd = GetAnalyzerChannelData( mSettings->mCmdChannel );
    mDAT0 = mSettings->mDAT0Channel == UNDEFINED_CHANNEL ? nullptr : GetAnalyzerChannelData( mSettings->mDAT0Channel );
    mDAT1 = mSettings->mDAT1Channel == UNDEFINED_CHANNEL ? nullptr : GetAnalyzerChannelData( mSettings->mDAT1Channel );
    mDAT2 = mSettings->mDAT2Channel == UNDEFINED_CHANNEL ? nullptr : GetAnalyzerChannelData( mSettings->mDAT2Channel );
    mDAT3 = mSettings->mDAT3Channel == UNDEFINED_CHANNEL ? nullptr : GetAnalyzerChannelData( mSettings->mDAT3Channel );

    // Drive decoding from the clock so we can analyze both CMD and DAT phases.
    mClock->AdvanceToNextEdge();
    {
        const U64 sampleNumber = mClock->GetSampleNumber();
        lastFallingClockEdge = sampleNumber;
        mCmd->AdvanceToAbsPosition( sampleNumber );
        if( mDAT0 )
            mDAT0->AdvanceToAbsPosition( sampleNumber );
        if( mDAT1 )
            mDAT1->AdvanceToAbsPosition( sampleNumber );
        if( mDAT2 )
            mDAT2->AdvanceToAbsPosition( sampleNumber );
        if( mDAT3 )
            mDAT3->AdvanceToAbsPosition( sampleNumber );
        prevCmd = mCmd->GetBitState();
        if( mDAT0 )
            prevDat0 = mDAT0->GetBitState();
    }

    for( ;; )
    {
        mClock->AdvanceToNextEdge();
        const U64 sampleNumber = mClock->GetSampleNumber();

        mCmd->AdvanceToAbsPosition( sampleNumber );
        if( mDAT0 )
            mDAT0->AdvanceToAbsPosition( sampleNumber );
        if( mDAT1 )
            mDAT1->AdvanceToAbsPosition( sampleNumber );
        if( mDAT2 )
            mDAT2->AdvanceToAbsPosition( sampleNumber );
        if( mDAT3 )
            mDAT3->AdvanceToAbsPosition( sampleNumber );

        if( mClock->GetBitState() == BIT_HIGH )
        {
            // Rising clock edge: sample CMD and DAT.
            mResults->AddMarker( sampleNumber, AnalyzerResults::UpArrow, mSettings->mClockChannel );

            // --- CMD start detection (start bit is 0, idle is 1) ---
            const BitState cmd_now = mCmd->GetBitState();
            if( !cmdActive )
            {
                if( prevCmd == BIT_HIGH && cmd_now == BIT_LOW )
                {
                    // Detected start bit; actual packet fields begin next clock.
                    cmdActive = true;
                    frameState = TRANSMISSION_BIT;
                    frameV2.reset( new FrameV2 );
                    // Mark the start bit on CMD.
                    mResults->AddMarker( lastFallingClockEdge, AnalyzerResults::MarkerType::Start, mSettings->mCmdChannel );
                }
            }
            else
            {
                if( FrameStateMachine() )
                    cmdActive = false;
            }

            // --- DAT start detection and decoding ---
            if( mDAT0 )
            {
                const BitState dat0_now = mDAT0->GetBitState();
                const bool have_4bit = ( mDAT1 && mDAT2 && mDAT3 );

                if( !dataActive )
                {
                    bool start_cond = false;
                    if( prevDat0 == BIT_HIGH && dat0_now == BIT_LOW )
                    {
                        if( have_4bit )
                        {
                            start_cond = ( mDAT1->GetBitState() == BIT_LOW ) && ( mDAT2->GetBitState() == BIT_LOW ) &&
                                         ( mDAT3->GetBitState() == BIT_LOW );
                        }
                        else
                        {
                            start_cond = true;
                        }
                    }

                    if( start_cond )
                    {
                        dataActive = true;
                        dataUsing4Bit = have_4bit;
                        dataNibbleCount = 0;
                        dataByteAcc = 0;
                        dataByteStartSample = lastFallingClockEdge;
                        dataIdleHighClocks = 0;
                        dataBytesDecodedInPhase = 0;

                        remainingDataBytes = expectedDataBytes;
                        trailerBitsRemaining = 0;

                        mResults->AddMarker( lastFallingClockEdge, AnalyzerResults::MarkerType::Start, mSettings->mDAT0Channel );
                    }
                }
                else
                {
                    if( trailerBitsRemaining > 0 )
                    {
                        trailerBitsRemaining--;
                        if( trailerBitsRemaining == 0 )
                        {
                            dataActive = false;
                            expectedDataBytes = 0; // consumed
                            mResults->AddMarker( sampleNumber, AnalyzerResults::MarkerType::Stop, mSettings->mDAT0Channel );
                        }
                    }
                    else
                    {
                        bool can_decode = true;

                        // Heuristic termination when we don't know the expected length.
                        // If all DAT lines are high for a while after having decoded at
                        // least one byte, we assume the data phase has ended.
                        if( remainingDataBytes == 0 )
                        {
                            const bool all_high = have_4bit ? ( mDAT0->GetBitState() == BIT_HIGH && mDAT1->GetBitState() == BIT_HIGH &&
                                                                mDAT2->GetBitState() == BIT_HIGH && mDAT3->GetBitState() == BIT_HIGH )
                                                            : ( mDAT0->GetBitState() == BIT_HIGH );
                            if( all_high )
                                dataIdleHighClocks++;
                            else
                                dataIdleHighClocks = 0;

                            if( dataBytesDecodedInPhase > 0 && dataIdleHighClocks >= 64 )
                            {
                                dataActive = false;
                                expectedDataBytes = 0;
                                mResults->AddMarker( sampleNumber, AnalyzerResults::MarkerType::Stop, mSettings->mDAT0Channel );
                                can_decode = false;
                            }
                        }

                        if( can_decode )
                        {
                            if( dataUsing4Bit )
                            {
                                const U8 nibble = ( ( U8 )mDAT3->GetBitState() << 3 ) | ( ( U8 )mDAT2->GetBitState() << 2 ) |
                                                  ( ( U8 )mDAT1->GetBitState() << 1 ) | ( ( U8 )mDAT0->GetBitState() << 0 );

                                if( dataNibbleCount == 0 )
                                {
                                    dataByteAcc = nibble;
                                    dataNibbleCount = 1;
                                    dataByteStartSample = lastFallingClockEdge;
                                }
                                else
                                {
                                    dataByteAcc = ( U8 )( ( dataByteAcc << 4 ) | nibble );
                                    dataNibbleCount = 0;

                                    Frame frame;
                                    frame.mStartingSampleInclusive = dataByteStartSample;
                                    frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
                                    frame.mFlags = 0;
                                    frame.mData1 = dataByteAcc;
                                    frame.mData2 = 4;
                                    frame.mType = FRAME_DATA;
                                    mResults->AddFrame( frame );

                                    FrameV2 data_frame;
                                    data_frame.AddByte( "DATA", dataByteAcc );
                                    mResults->AddFrameV2( data_frame, "DATA", frame.mStartingSampleInclusive,
                                                          frame.mEndingSampleInclusive );
                                    dataBytesDecodedInPhase++;

                                    if( remainingDataBytes > 0 )
                                    {
                                        remainingDataBytes--;
                                        if( remainingDataBytes == 0 )
                                        {
                                            // CRC16 (16 clocks) + end bit (1 clock) for each line,
                                            // transmitted in parallel.
                                            trailerBitsRemaining = 17;
                                        }
                                    }
                                }
                            }
                            else
                            {
                                // 1-bit mode: sample DAT0 serially.
                                if( dataNibbleCount == 0 )
                                    dataByteStartSample = lastFallingClockEdge;
                                dataByteAcc = ( U8 )( ( dataByteAcc << 1 ) | ( U8 )mDAT0->GetBitState() );
                                dataNibbleCount++;
                                if( dataNibbleCount == 8 )
                                {
                                    Frame frame;
                                    frame.mStartingSampleInclusive = dataByteStartSample;
                                    frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
                                    frame.mFlags = 0;
                                    frame.mData1 = dataByteAcc;
                                    frame.mData2 = 1;
                                    frame.mType = FRAME_DATA;
                                    mResults->AddFrame( frame );

                                    FrameV2 data_frame;
                                    data_frame.AddByte( "DATA", dataByteAcc );
                                    mResults->AddFrameV2( data_frame, "DATA", frame.mStartingSampleInclusive,
                                                          frame.mEndingSampleInclusive );
                                    dataBytesDecodedInPhase++;

                                    dataNibbleCount = 0;
                                    dataByteAcc = 0;

                                    if( remainingDataBytes > 0 )
                                    {
                                        remainingDataBytes--;
                                        if( remainingDataBytes == 0 )
                                            trailerBitsRemaining = 17;
                                    }
                                }
                            }
                        }
                    }
                }

                prevDat0 = dat0_now;
            }

            prevCmd = cmd_now;
        }
        else
        {
            // Falling edge.
            lastFallingClockEdge = sampleNumber;
        }

        mResults->CommitResults();
        ReportProgress( sampleNumber );
    }
}

// Determine whether or not we are in a packet
void SDIOAnalyzer::PacketStateMachine()
{
    if( packetState == WAITING_FOR_PACKET )
    {
        // If we are not in a packet, let's advance to the next edge on the
        // command line
        mCmd->AdvanceToNextEdge();
        U64 sampleNumber = mCmd->GetSampleNumber();
        lastFallingClockEdge = sampleNumber;
        mClock->AdvanceToAbsPosition( sampleNumber );
        // After advancing to the next command line edge the clock can either
        // high or low.  If it is high, we need to advance two clock edges.  If
        // it is low, we only need to advance one clock edge.
        if( mClock->GetBitState() == BIT_HIGH )
        {
            mClock->AdvanceToNextEdge();
        }

        mClock->AdvanceToNextEdge();
        sampleNumber = mClock->GetSampleNumber();

        mCmd->AdvanceToAbsPosition( sampleNumber );
        if( mDAT0 )
            mDAT0->AdvanceToAbsPosition( sampleNumber );
        if( mDAT1 )
            mDAT1->AdvanceToAbsPosition( sampleNumber );
        if( mDAT2 )
            mDAT2->AdvanceToAbsPosition( sampleNumber );
        if( mDAT3 )
            mDAT3->AdvanceToAbsPosition( sampleNumber );

        if( mCmd->GetBitState() == BIT_LOW )
        {
            packetState = IN_PACKET;
        }
    }
    else if( packetState == IN_PACKET )
    {
        mClock->AdvanceToNextEdge();
        U64 sampleNumber = mClock->GetSampleNumber();

        mCmd->AdvanceToAbsPosition( sampleNumber );
        if( mDAT0 )
            mDAT0->AdvanceToAbsPosition( sampleNumber );
        if( mDAT1 )
            mDAT1->AdvanceToAbsPosition( sampleNumber );
        if( mDAT2 )
            mDAT2->AdvanceToAbsPosition( sampleNumber );
        if( mDAT3 )
            mDAT3->AdvanceToAbsPosition( sampleNumber );

        if( mClock->GetBitState() == BIT_HIGH )
        {
            mResults->AddMarker( mClock->GetSampleNumber(), AnalyzerResults::UpArrow, mSettings->mClockChannel );
            if( FrameStateMachine() )
            {
                packetState = WAITING_FOR_PACKET;
            }
        }
        else
        {
            lastFallingClockEdge = mClock->GetSampleNumber();
        }
    }
}

// This state machine will deal with accepting the different parts of the
// transmitted information.  In order to correctly interpret the data stream,
// we need to be able to distinguish between 4 different kinds of packets.
// They are:
//  - Command
//  - Short Response
//  - Long Response
//  - Data

bool SDIOAnalyzer::FrameStateMachine( void )
{
    Frame frame;
    bool done = false;
    U8 respLength;

    switch( frameState )
    {
    case TRANSMISSION_BIT:
        frame.mStartingSampleInclusive = lastFallingClockEdge;
        frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
        frame.mFlags = 0;
        frame.mData1 = mCmd->GetBitState();
        frame.mType = FRAME_DIR;
        mResults->AddFrame( frame );

        frameV2->AddBoolean( "DIR", frame.mData1 );
        startingSampleInclusive = frame.mStartingSampleInclusive;

        // The transmission bit tells us the origin of the packet
        // If the bit is high the packet comes from the host
        // If the bit is low, the packet comes from the slave
        isCmd = mCmd->GetBitState();

        mResults->AddMarker( lastFallingClockEdge, SDIOAnalyzerResults::MarkerType::Start, mSettings->mCmdChannel );
        if( isCmd )
        {
            mResults->AddMarker( mClock->GetSampleNumber(), SDIOAnalyzerResults::MarkerType::One, mSettings->mCmdChannel );
        }
        else
        {
            mResults->AddMarker( mClock->GetSampleNumber(), SDIOAnalyzerResults::MarkerType::Zero, mSettings->mCmdChannel );
        }

        frameState = COMMAND;
        frameCounter = 6;

        qwordLow = 0;
        lastCommand = 0;
        expectedCRC = 0;
        startOfNextFrame = UINT64_MAX;
        break;

    case COMMAND:
        startOfNextFrame = std::min( startOfNextFrame, lastFallingClockEdge );
        qwordLow = ( qwordLow << 1 ) | mCmd->GetBitState();
        frameCounter--;

        if( frameCounter == 0 )
        {
            frame.mStartingSampleInclusive = startOfNextFrame;
            frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
            frame.mFlags = 0;
            frame.mData1 = qwordLow & 0x3F;
            frame.mData2 = isCmd ? 1 : 0;
            frame.mType = FRAME_CMD;

            mResults->AddFrame( frame );
            mResults->AddMarker( startOfNextFrame + 1, SDIOAnalyzerResults::MarkerType::Dot, mSettings->mCmdChannel );

            {
                char cmd_str[ 8 ];
                std::snprintf( cmd_str, sizeof( cmd_str ), "%u", static_cast<unsigned>( frame.mData1 ) );
                frameV2->AddString( "CMD", cmd_str );
            }
            frameV2->AddBoolean( "DIR", frame.mData2 );

            expectedCRC = sdCRC7( 0, ( frame.mData2 << 6 ) | frame.mData1 );

            // Once we have the argument

            lastCommand = frame.mData1;

            // Find the expected length of the next response based on the command
            if( !isCmd && ( qwordLow == 2 || qwordLow == 9 || qwordLow == 10 ) )
            // CMD2, CMD9 and CMD10 respond with long R2 response
            {
                respLength = 127;
                frameState = LONG_ARGUMENT;
            }
            else
            {
                // All others have 48 bit responses
                respLength = 32;
                frameState = NORMAL_ARGUMENT;
            }

            byte = 0;
            qwordLow = 0;
            byteCounter = 0;
            frameCounter = respLength;
            startOfNextFrame = UINT64_MAX;
        }
        break;

    case NORMAL_ARGUMENT:
        startOfNextFrame = std::min( startOfNextFrame, lastFallingClockEdge );
        byte = byte << 1 | mCmd->GetBitState();
        qwordLow = ( qwordLow << 1 ) | mCmd->GetBitState();

        frameCounter--;

        if( ( frameCounter ) % 8 == 0 )
        {
            data[ byteCounter ] = byte;
            byteCounter++;
            byte = 0;
        }

        if( frameCounter == 0 )
        {
            frame.mStartingSampleInclusive = startOfNextFrame;
            frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
            frame.mFlags = lastCommand;
            frame.mData1 = qwordLow;
            frame.mType = FRAME_ARG;

            mResults->AddFrame( frame );
            mResults->AddMarker( startOfNextFrame + 1, SDIOAnalyzerResults::MarkerType::Square, mSettings->mCmdChannel );

            frameV2->AddByteArray( "ARG", data, 4 );
            const std::string parsing = BuildParsingString( lastCommand, ( U32 )frame.mData1, isCmd );
            if( !parsing.empty() )
                frameV2->AddString( "PARSING", parsing.c_str() );

            if( isCmd )
                lastArg32 = ( U32 )frame.mData1;

            for( signed int i = 24; i >= 0; i -= 8 )
                expectedCRC = sdCRC7( expectedCRC, 0xFF & ( frame.mData1 >> i ) );

            frameState = CRC7;
            frameCounter = 7;
            qwordLow = 0;
            startOfNextFrame = UINT64_MAX;
        }
        break;

    case LONG_ARGUMENT:
        startOfNextFrame = std::min( startOfNextFrame, lastFallingClockEdge );
        byte = byte << 1 | mCmd->GetBitState();
        qwordLow = ( qwordLow << 1 ) | mCmd->GetBitState();

        frameCounter--;

        if( frameCounter % 8 == 0 )
        {
            data[ byteCounter ] = byte;
        }

        if( frameCounter == 63 )
        {
            qwordHigh = qwordLow;
            qwordLow = 0;
        }

        if( frameCounter == 0 )
        {
            frame.mStartingSampleInclusive = startOfNextFrame;
            frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
            frame.mFlags = lastCommand;
            frame.mData1 = qwordHigh;
            frame.mData2 = qwordLow;
            frame.mType = FRAME_LONG_ARG;
            mResults->AddFrame( frame );
            mResults->AddMarker( startOfNextFrame + 1, SDIOAnalyzerResults::MarkerType::Square, mSettings->mCmdChannel );

            frameV2->AddByteArray( "ARG", data, 8 );

            for( signed int i = 24; i >= 0; i -= 8 )
                expectedCRC = sdCRC7( expectedCRC, 0xFF & ( frame.mData1 >> i ) );

            for( signed int i = 24; i >= 0; i -= 8 )
                expectedCRC = sdCRC7( expectedCRC, 0xFF & ( frame.mData2 >> i ) );

            frameState = STOP;
            frameCounter = 1;
            qwordLow = 0;
            startOfNextFrame = UINT64_MAX;
        }
        break;

    case CRC7:
        startOfNextFrame = std::min( startOfNextFrame, lastFallingClockEdge );
        qwordLow = qwordLow << 1 | mCmd->GetBitState();
        frameCounter--;

        if( frameCounter == 0 )
        {
            qwordLow &= 0x7F;

            frame.mStartingSampleInclusive = startOfNextFrame;
            frame.mEndingSampleInclusive = mClock->GetSampleOfNextEdge();
            frame.mFlags = 0;
            frame.mData1 = qwordLow;
            frame.mData2 = ( qwordLow == expectedCRC );
            frame.mType = FRAME_CRC;
            mResults->AddFrame( frame );

            if( frame.mData2 )
            {
                mResults->AddMarker( startOfNextFrame + 1, SDIOAnalyzerResults::MarkerType::X, mSettings->mCmdChannel );
            }
            else
            {
                mResults->AddMarker( startOfNextFrame + 1, SDIOAnalyzerResults::MarkerType::ErrorX, mSettings->mCmdChannel );
            }

            frameV2->AddByte( "CRC", frame.mData1 );
            frameV2->AddBoolean( "PASS", frame.mData2 );
            endingSampleInclusive = frame.mEndingSampleInclusive;

            frameState = STOP;
            qwordLow = 0;
        }
        break;

    case STOP:
        mResults->AddMarker( mClock->GetSampleNumber(), SDIOAnalyzerResults::MarkerType::Stop, mSettings->mCmdChannel );

        // Best-effort: infer expected data length for CMD53 (IO_RW_EXTENDED).
        // This lets the DAT decoder stop at a deterministic point instead of
        // relying on heuristics.
        if( isCmd && lastCommand == 53 )
        {
            // Argument fields per SDIO spec:
            // [31] RW flag, [27] block mode, [8:0] count (0 => 512)
            const bool block_mode = ( ( lastArg32 >> 27 ) & 0x1 ) != 0;
            U32 count = lastArg32 & 0x1FF;
            if( count == 0 )
                count = 512;

            if( !block_mode )
            {
                expectedDataBytes = count;
            }
            else
            {
                // Block size is configurable and not known here. 512 is a
                // common/default; this is still useful.
                expectedDataBytes = count * 512;
            }
        }

        if( isCmd )
        {
            mResults->AddFrameV2( *frameV2, "CMD", startingSampleInclusive, endingSampleInclusive );
        }
        else
        {
            mResults->AddFrameV2( *frameV2, "RESP", startingSampleInclusive, endingSampleInclusive );
        }
        frameV2.reset( new FrameV2 );
        frameState = TRANSMISSION_BIT;
        done = true;

    default:
        break;
    }

    return done;
}

bool SDIOAnalyzer::NeedsRerun( void )
{
    return ( !mAlreadyRun );
}

U32 SDIOAnalyzer::GenerateSimulationData( U64 minimum_sample_index, U32 device_sample_rate,
                                          SimulationChannelDescriptor** simulation_channels )
{
    return 0;
}

U32 SDIOAnalyzer::GetMinimumSampleRateHz( void )
{
    return 25000;
}

const char* SDIOAnalyzer::GetAnalyzerName( void ) const
{
    return "SDIO";
}

const char* GetAnalyzerName( void )
{
    return "SDIO";
}

Analyzer* CreateAnalyzer( void )
{
    return new SDIOAnalyzer();
}

void DestroyAnalyzer( Analyzer* analyzer )
{
    delete analyzer;
}
