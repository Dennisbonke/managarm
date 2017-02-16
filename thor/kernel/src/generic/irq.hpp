#ifndef THOR_GENERIC_IRQ_HPP
#define THOR_GENERIC_IRQ_HPP

#include <frigg/debug.hpp>
#include <frigg/linked.hpp>
#include <frg/list.hpp>
#include "error.hpp"

namespace thor {

struct AwaitIrqBase {
	virtual void complete(Error error) = 0;

	frigg::IntrusiveSharedLinkedItem<AwaitIrqBase> processQueueItem;
};

template<typename F>
struct AwaitIrq : AwaitIrqBase {
	AwaitIrq(F functor)
	: _functor(frigg::move(functor)) { }

	void complete(Error error) override {
		_functor(error);
	}

private:
	F _functor;
};

// ----------------------------------------------------------------------------

struct IrqPin;

// Represents a slot in the CPU's interrupt table.
// Slots might be global or per-CPU.
struct IrqSlot {
	// Links an IrqPin to this slot.
	// From now on all IRQ raises will go to this IrqPin.
	void link(IrqPin *pin);

	// The kernel calls this function when an IRQ is raised.
	void raise();

private:
	IrqPin *_pin;
};

// ----------------------------------------------------------------------------

struct IrqSink {
	friend void attachIrq(IrqPin *pin, IrqSink *sink);

	IrqSink();

	virtual void raise() = 0;

	// TODO: This needs to be thread-safe.
	IrqPin *getPin();

	frg::default_list_hook<IrqSink> hook;

private:
	IrqPin *_pin;
};

enum class IrqStrategy {
	null,
	justEoi,
	maskThenEoi
};

enum class TriggerMode {
	null,
	edge,
	level
};

enum class Polarity {
	null,
	high,
	low
};

// Represents a (not necessarily physical) "pin" of an interrupt controller.
// This class handles the IRQ configuration and acknowledgement.
struct IrqPin {
	friend void attachIrq(IrqPin *pin, IrqSink *sink);
private:
	using Mutex = frigg::TicketLock;

public:
	IrqPin();

	IrqPin(const IrqPin &) = delete;
	
	IrqPin &operator= (const IrqPin &) = delete;

	void configure(TriggerMode mode, Polarity polarity);

	// This function is called from IrqSlot::raise().
	void raise();

	void acknowledge();

protected:
	virtual IrqStrategy program(TriggerMode mode, Polarity polarity) = 0;

	virtual void mask() = 0;
	virtual void unmask() = 0;

	// Sends an end-of-interrupt signal to the interrupt controller.
	virtual void sendEoi() = 0;

private:
	void _callSinks();

	Mutex _mutex;

	IrqStrategy _strategy;

	// TODO: This list should change rarely. Use a RCU list.
	frg::intrusive_list<
		IrqSink,
		frg::locate_member<
			IrqSink,
			frg::default_list_hook<IrqSink>,
			&IrqSink::hook
		>
	> _sinkList;
};

void attachIrq(IrqPin *pin, IrqSink *sink);

// ----------------------------------------------------------------------------

// This class implements the user-visible part of IRQ handling.
struct IrqObject : IrqSink {
	IrqObject();

	void raise() override;

	void submitAwait(frigg::SharedPtr<AwaitIrqBase> wait);
	
	void acknowledge();
	
private:
	bool _latched;

	frigg::IntrusiveSharedLinkedList<
		AwaitIrqBase,
		&AwaitIrqBase::processQueueItem
	> _waitQueue;
};

} // namespace thor

#endif // THOR_GENERIC_IRQ_HPP
