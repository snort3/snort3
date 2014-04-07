//-------------------------------------------------------------------
// simple ring logic
//-------------------------------------------------------------------

#ifndef RING_LOGIC_H
#define RING_LOGIC_H

class RingLogic {
public:
    RingLogic(int size);

    // return next available position or -1
    int read();
    int write();

    // return true if index advanced
    bool push();
    bool pop();

    int count();
    bool full();
    bool empty();

private:
    int next(int ix)
    { return ( ++ix < sz ) ? ix : 0; };

private:
    int sz;
    volatile int rx;
    volatile int wx;
};

inline RingLogic::RingLogic(int size)
{
    sz = size;
    rx = 0;
    wx = 1;
}

inline int RingLogic::read()
{
    int nx = next(rx);
    return ( nx == wx ) ? -1 : nx;
}

inline int RingLogic::write()
{
    int nx = next(wx);
    return ( nx == rx ) ? -1 : wx;
}

inline bool RingLogic::push()
{
    int nx = next(wx);
    if ( nx == rx )
        return false;
    wx = nx;
    return true;
}

inline bool RingLogic::pop()
{
    int nx = next(rx);
    if ( nx == wx )
        return false;
    rx = nx;
    return true;
}

inline int RingLogic::count()
{
    int c = wx - rx - 1;
    if ( c < 0 ) c += sz;
    return c;
}

inline bool RingLogic::full()
{
    return ( count() == sz );
}

inline bool RingLogic::empty()
{
    return ( count() == 0 );
}
#endif

